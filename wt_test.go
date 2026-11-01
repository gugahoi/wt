package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The test binary also stands in for tmux and rex, and for wt itself when wt runs itself in the background:
// tmux and rex are stubs on PATH that log their arguments, and files in $WT_STUB_DIR change their answers.
// rex's exit codes are the real ones. No network, tmux or Rex needed.
func TestMain(m *testing.M) {
	if name := filepath.Base(os.Args[0]); name == "tmux" || name == "rex" {
		os.Exit(stub(name, os.Args[1:]))
	}
	if os.Getenv("WT_TEST_MAIN") != "" {
		os.Exit(run(os.Args[1:]))
	}
	os.Setenv("WT_TEST_MAIN", "1")
	os.Exit(m.Run())
}

// Trimmed from real --json output of rex 0.0.1793131181 (API revision 7).
var rexInspect = map[string]any{
	"client": map[string]any{"client_id": "client:01a1800a-b4f1-71d8-be7a-e38922f26a90", "info": map[string]any{"kind": "app", "name": "Rex Beta"}},
	"actions": []any{
		map[string]any{"name": "session.new", "kind": "client", "title": "New Session"},
		map[string]any{"name": "session.select", "kind": "client", "title": "Go to Session", "args": map[string]any{
			"type": "object", "required": []any{"session_id"},
			"properties": map[string]any{"session_id": map[string]any{"type": "string"}, "window_id": map[string]any{"type": "string"}}}},
	},
}

var (
	rexWhoamiLive = map[string]any{
		"rex_version": "0.0.1793131181-gdd9a20", "session_count": 1,
		"session_id": "session:01a17fee-578c-79ac-9f5b-e1594ece24e4",
		"window_id":  "window:01a17ff4-aea6-7a3d-a9a5-c05238a0d8ca",
		"block_id":   "block:01a17ff4-ae83-7b89-9991-87047c89f2e5",
	}
	rexWhoamiStale = map[string]any{"rex_version": "0.0.1793131181-gdd9a20", "session_count": 1}
)

func stub(name string, args []string) int {
	state := os.Getenv("WT_STUB_DIR")
	call, _ := json.Marshal(append([]string{name}, args...))
	log, _ := os.OpenFile(filepath.Join(state, "calls"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	log.Write(append(call, '\n'))
	log.Close()
	read := func(file string, fallback any) any {
		data, err := os.ReadFile(filepath.Join(state, file))
		if err != nil {
			return fallback
		}
		var v any
		json.Unmarshal(data, &v)
		return v
	}
	fail := func(file string, code int) {
		if data, err := os.ReadFile(filepath.Join(state, file)); err == nil {
			os.Stderr.Write(data)
			os.Exit(code)
		}
	}
	print := func(v any) { data, _ := json.Marshal(v); fmt.Println(string(data)) }

	if name == "tmux" {
		if _, err := os.Stat(filepath.Join(state, "tmux-has-session")); err != nil && args[0] == "has-session" {
			return 1
		}
		return 0
	}
	for strings.HasPrefix(args[0], "--") {
		args = args[1:]
	}
	switch args[0] {
	case "whoami":
		print(read("whoami.json", map[string]any{}))
	case "client":
		fail("client-error", 3)
		print(read("inspect.json", rexInspect))
	case "ls":
		print(map[string]any{"sessions": read("sessions.json", []any{})})
	case "new":
		sessions := read("sessions.json", []any{}).([]any)
		id := fmt.Sprintf("session:01a1801a-0000-7000-8000-%012d", len(sessions))
		data, _ := json.Marshal(append(sessions, map[string]any{"session_id": id, "label": args[1]}))
		os.WriteFile(filepath.Join(state, "sessions.json"), data, 0o644)
		fail("new-error", 1)
		print(map[string]any{"session_id": id, "initial_windows": []any{
			map[string]any{"window_id": "window:01a1801a-0000-7000-8000-000000000000", "block_ids": []any{}, "revision": 1}}})
	case "do":
		fail("do-error", 1)
	}
	return 0
}

type fixture struct {
	t                  *testing.T
	root, repo, remote string
	stubs, stubState   string
	stderr             bytes.Buffer
	pickerShown        bool
	defaultPath        string
}

// setup makes a repository with an origin, whose main is pushed, and runs the test in it. Pickers fail
// the test unless it sets pick.
func setup(t *testing.T) *fixture {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, root: root, repo: filepath.Join(root, "repo"), remote: filepath.Join(root, "remote.git"),
		stubs: filepath.Join(root, "stubs"), stubState: filepath.Join(root, "stub-state")}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{f.stubs, f.stubState, f.repo} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"tmux", "rex"} {
		if err := os.Symlink(exe, filepath.Join(f.stubs, name)); err != nil {
			t.Fatal(err)
		}
	}
	// Inherited from the terminal running the tests, these would point wt at a live tmux or Rex.
	for _, name := range []string{"TMUX", "TMUX_PANE", "REX_SESSION", "REX_BLOCK", "REX_CLIENT", "WT_MULTIPLEXER", "WT_REFRESHED", "FZF_PROMPT"} {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
	t.Setenv("WT_STUB_DIR", f.stubState)
	f.defaultPath = f.stubs + string(os.PathListSeparator) + os.Getenv("PATH")
	t.Setenv("PATH", f.defaultPath)
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Chdir(f.repo)

	f.run("git", "init", "--bare", "-q", "-b", "main", f.remote)
	f.git("init", "-q", "-b", "main")
	f.git("config", "user.name", "Test")
	f.git("config", "user.email", "test@example.com")
	f.git("commit", "-q", "--allow-empty", "-m", "base")
	f.git("remote", "add", "origin", f.remote)
	f.git("push", "-q", "-u", "origin", "main")
	f.git("remote", "set-head", "origin", "main")

	mux = ""
	errOut = &f.stderr
	pick = func(input []string, args ...string) ([]string, int) {
		t.Fatalf("unexpected picker %q", args)
		return nil, 0
	}
	t.Cleanup(func() { mux, errOut, pick = "", os.Stderr, runFzf })
	return f
}

func (f *fixture) run(name string, args ...string) string {
	f.t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		f.t.Fatalf("%s %q: %v\n%s", name, args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (f *fixture) git(args ...string) string {
	f.t.Helper()
	return f.run("git", args...)
}

// wt runs the wt binary, returning its stdout and stderr, and whether it succeeded.
func (f *fixture) wt(args ...string) (string, string, bool) {
	exe, _ := os.Executable()
	cmd := exec.Command(exe, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err == nil
}

// picks makes pickers answer with the given output and exit code, recording that they were shown.
func (f *fixture) picks(out []string, code int) {
	pick = func([]string, ...string) ([]string, int) {
		f.pickerShown = true
		return out, code
	}
}

func (f *fixture) calls() [][]string {
	data, err := os.ReadFile(filepath.Join(f.stubState, "calls"))
	if err != nil {
		return nil
	}
	var calls [][]string
	for _, line := range lines(string(data)) {
		var call []string
		json.Unmarshal([]byte(line), &call)
		calls = append(calls, call)
	}
	return calls
}

// stubs changes a stub's answer: a JSON value to return, or an error message to fail with.
func (f *fixture) stub(file string, value any) {
	data, ok := value.(string)
	if !ok {
		encoded, _ := json.Marshal(value)
		data = string(encoded)
	}
	if err := os.WriteFile(filepath.Join(f.stubState, file), []byte(data), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) resetStubs() {
	entries, _ := os.ReadDir(f.stubState)
	for _, e := range entries {
		os.Remove(filepath.Join(f.stubState, e.Name()))
	}
}

// pathWithout is a PATH with git and the tmux/rex stubs, except those missing.
func (f *fixture) pathWithout(missing ...string) string {
	dir := filepath.Join(f.root, "path-without-"+strings.Join(missing, "-"))
	if _, err := os.Stat(dir); err == nil {
		return dir
	}
	os.Mkdir(dir, 0o755)
	for _, name := range []string{"git", "sh", "tmux", "rex"} {
		if found, err := exec.LookPath(name); err == nil && !slices.Contains(missing, name) {
			os.Symlink(found, filepath.Join(dir, name))
		}
	}
	return dir
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// rows are the branch picker's rows, by branch, without colours.
func (f *fixture) rows() map[string][]string {
	rows := map[string][]string{}
	for _, line := range listBranches() {
		fields := strings.Split(ansi.ReplaceAllString(line, ""), "\t")
		rows[fields[0]] = fields[1:]
	}
	return rows
}

func (f *fixture) remoteBranch(name string) {
	f.git("branch", name)
	f.git("push", "-q", "origin", name)
	f.git("branch", "-D", name)
}

// deleteSelected deletes as Ctrl-X in the picker does, confirming a remote deletion with choice, and waits
// for the background deletion. Only the confirmation is mocked: git deletes for real, from the throwaway remote.
func (f *fixture) deleteSelected(ref, name, choice string) {
	f.t.Helper()
	f.picks([]string{choice}, 0)
	process, err := deleteSelected(ref, name)
	if err != nil {
		f.t.Fatal(err)
	}
	if process != nil {
		process.Wait()
	}
}

func (f *fixture) hasRef(ref string) bool {
	return exec.Command("git", "show-ref", "--verify", "--quiet", ref).Run() == nil
}

func (f *fixture) remoteHasRef(ref string) bool {
	return exec.Command("git", "--git-dir="+f.remote, "show-ref", "--verify", "--quiet", ref).Run() == nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func gitHash(text string) string {
	sum := sha1.Sum([]byte(fmt.Sprintf("blob %d\x00%s", len(text), text)))
	return hex.EncodeToString(sum[:])
}

// Worktree picker

func TestRemoteOnlyLabelAndLocalTipPrecedence(t *testing.T) {
	f := setup(t)
	f.remoteBranch("remote-only")
	f.git("checkout", "-q", "-b", "both")
	f.git("push", "-q", "origin", "both")
	f.git("commit", "-q", "--allow-empty", "-m", "unmerged local work")
	f.git("checkout", "-q", "main")
	rows := f.rows()
	if !strings.Contains(rows["remote-only"][0], "[remote-only: origin/remote-only]") || rows["remote-only"][1] != "refs/remotes/origin/remote-only" {
		t.Errorf("remote-only: %q", rows["remote-only"])
	}
	both := rows["both"]
	if strings.Contains(both[0], "remote-only") || strings.Contains(both[0], "[merged]") ||
		!strings.Contains(both[0], "last commit:") || both[1] != "refs/heads/both" {
		t.Errorf("both: %q", both)
	}
	if _, ok := rows["HEAD"]; ok {
		t.Error("HEAD listed")
	}
}

func TestLocalDeletionPreservesRemoteAndRelabelsEntry(t *testing.T) {
	f := setup(t)
	f.git("branch", "both")
	f.git("push", "-q", "origin", "both")
	f.deleteSelected("refs/heads/both", "both", "Cancel")
	if f.hasRef("refs/heads/both") || !f.remoteHasRef("refs/heads/both") {
		t.Error("deleted the wrong branch")
	}
	if !strings.Contains(f.rows()["both"][0], "[remote-only: origin/both]") {
		t.Errorf("not relabelled: %q", f.rows()["both"])
	}
}

func TestLocalBranchWithoutWorktreeIsDeleted(t *testing.T) {
	f := setup(t)
	f.git("branch", "local-only")
	f.deleteSelected("refs/heads/local-only", "local-only", "Cancel")
	if _, ok := f.rows()["local-only"]; ok {
		t.Error("still listed")
	}
}

func TestWorktreeDeletion(t *testing.T) {
	f := setup(t)
	worktree := filepath.Join(f.root, "active")
	f.git("worktree", "add", "-q", "-b", "123-active", worktree)
	if _, ok := f.rows()["123-active [wt]"]; !ok {
		t.Fatal("worktree not tagged")
	}
	f.deleteSelected("refs/heads/123-active", "123-active [wt]", "Cancel")
	if exists(worktree) || f.hasRef("refs/heads/123-active") {
		t.Error("worktree or branch left")
	}
}

func TestCancelOrAbortPreservesRemote(t *testing.T) {
	f := setup(t)
	f.remoteBranch("keep")
	f.deleteSelected("refs/remotes/origin/keep", "keep", "Cancel")
	f.picks(nil, 130)
	if process, err := deleteSelected("refs/remotes/origin/keep", "keep"); process != nil || err != nil {
		t.Fatal("deletion started", err)
	}
	if !f.remoteHasRef("refs/heads/keep") || !f.hasRef("refs/remotes/origin/keep") {
		t.Error("remote branch deleted")
	}
}

func TestConfirmedRemoteDeletionHandlesSlashes(t *testing.T) {
	f := setup(t)
	f.remoteBranch("feature/nested")
	f.deleteSelected("refs/remotes/origin/feature/nested", "feature/nested", "Delete remote branch")
	if f.remoteHasRef("refs/heads/feature/nested") || f.hasRef("refs/remotes/origin/feature/nested") {
		t.Error("remote branch left")
	}
	if _, ok := f.rows()["feature/nested"]; ok {
		t.Error("still listed")
	}
}

func TestRejectedRemoteDeletionIsVisibleAndRetryable(t *testing.T) {
	f := setup(t)
	f.remoteBranch("protected")
	hook := filepath.Join(f.remote, "hooks/pre-receive")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\necho 'Deletion forbidden' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.deleteSelected("refs/remotes/origin/protected", "protected", "Delete remote branch")
	if !f.remoteHasRef("refs/heads/protected") || !f.hasRef("refs/remotes/origin/protected") {
		t.Error("deleted despite the rejection")
	}
	if h := header(); !strings.Contains(h, "Deletion of 'protected' failed") || !strings.Contains(h, "Deletion forbidden") {
		t.Errorf("header: %q", h)
	}
	if pending, _ := os.ReadDir(filepath.Join(f.repo, ".git/wt-state/pending")); len(pending) != 0 {
		t.Errorf("pending: %v", pending)
	}
}

func TestLocalDeletionFailureIsVisible(t *testing.T) {
	f := setup(t)
	// The branch became current between listing and deleting it.
	f.deleteSelected("refs/heads/main", "main", "Cancel")
	if !f.hasRef("refs/heads/main") {
		t.Error("main deleted")
	}
	if h := header(); !strings.Contains(h, "Deletion of 'main' failed") {
		t.Errorf("header: %q", h)
	}
}

func TestOtherRemoteUsesExactRefForDeletion(t *testing.T) {
	f := setup(t)
	f.remoteBranch("topic")
	f.git("remote", "add", "upstream", f.remote)
	f.git("fetch", "-q", "upstream")
	if row := f.rows()["upstream/topic"]; !strings.Contains(row[0], "[remote-only: upstream/topic]") {
		t.Errorf("row: %q", row)
	}
	f.deleteSelected("refs/remotes/upstream/topic", "upstream/topic", "Delete remote branch")
	if f.remoteHasRef("refs/heads/topic") || f.hasRef("refs/remotes/upstream/topic") {
		t.Error("remote branch left")
	}
}

func TestRemoteSelectionSwitchesAndIssueMarkersSurvive(t *testing.T) {
	f := setup(t)
	f.remoteBranch("123-topic")
	f.git("remote", "add", "upstream", f.remote)
	f.git("fetch", "-q", "upstream")
	row := f.rows()["upstream/123-topic"]
	if err := switchToBranch("upstream/123-topic\t" + strings.Join(row, "\t")); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	want := []string{"tmux", "new-session", "-A", "-s", "123-topic", "-c", filepath.Join(f.repo, "123-topic")}
	if calls := f.calls(); !slices.ContainsFunc(calls, func(c []string) bool { return slices.Equal(c, want) }) {
		t.Errorf("calls: %q", calls)
	}
	if remote := f.git("config", "branch.123-topic.remote"); remote != "upstream" {
		t.Errorf("tracks %q", remote)
	}
	if err := writeCache("issues", []string{"123\t2026-01-01\tTest issue\t"}); err != nil {
		t.Fatal(err)
	}
	if tags := strings.Split(issueLines()[0], "\t")[4]; strings.TrimSpace(tags) != "[wt]" {
		t.Errorf("tags %q", tags)
	}
}

func decode[T any](t *testing.T, data string) []T {
	t.Helper()
	var items []T
	if err := json.Unmarshal([]byte(data), &items); err != nil {
		t.Fatal(err)
	}
	return items
}

func TestIssuesAndPRsAreNewestFirst(t *testing.T) {
	f := setup(t)
	f.git("branch", "1-old") // a branch no longer lifts its issue to the top
	issues := decode[issue](t, `[
		{"number": 1, "createdAt": "2026-01-01", "updatedAt": "2026-01-01", "title": "t", "labels": {"nodes": []}},
		{"number": 3, "createdAt": "2026-03-01", "updatedAt": "2026-03-01", "title": "t", "labels": {"nodes": []}},
		{"number": 2, "createdAt": "2026-02-01", "updatedAt": "2026-02-01", "title": "t", "labels": {"nodes": []}}]`)
	var prs []pullRequest
	for _, pr := range []struct {
		n       int
		created string
		draft   bool
	}{{4, "2026-01-01", false}, {5, "2026-02-01", true}, {6, "2026-03-01", false}, {7, "2026-04-01", true}} {
		prs = append(prs, pullRequest{Number: pr.n, CreatedAt: pr.created, UpdatedAt: pr.created, IsDraft: pr.draft,
			HeadRefName: fmt.Sprintf("b%d", pr.n), Title: "t", Author: &actor{Login: "me"}})
	}
	if err := writeCache("issues", issueCacheLines(issues)); err != nil {
		t.Fatal(err)
	}
	if err := writeCache("prs", prCacheLines(prs)); err != nil {
		t.Fatal(err)
	}
	var numbers []string
	for _, line := range append(cmdLines([]string{"issue"}), cmdLines([]string{"pr"})...) {
		numbers = append(numbers, strings.Split(line, "\t")[1])
	}
	if want := []string{"3", "2", "1", "6", "4", "7", "5"}; !slices.Equal(numbers, want) {
		t.Errorf("got %v, want %v", numbers, want)
	}
}

func TestPRReviewStatus(t *testing.T) {
	setup(t)
	prs := decode[pullRequest](t, `[
		{"number": 1, "createdAt": "2026-01-01", "author": {"__typename": "Bot", "login": "dependabot"},
		 "reviewRequests": {"nodes": [{"requestedReviewer": {}}]}},
		{"number": 2, "createdAt": "2026-01-02", "author": {"login": "me"}, "reviews": {"nodes": [
			{"author": {"login": "bot"}, "authorAssociation": "NONE", "state": "APPROVED"},
			{"author": {"login": "me"}, "authorAssociation": "OWNER", "state": "COMMENTED"},
			{"author": {"login": "you"}, "authorAssociation": "MEMBER", "state": "PENDING"}]}},
		{"number": 3, "createdAt": "2026-01-03", "author": {"login": "me"}, "reviews": {"nodes": [
			{"author": {"login": "a"}, "authorAssociation": "MEMBER", "state": "APPROVED"},
			{"author": {"login": "a"}, "authorAssociation": "MEMBER", "state": "COMMENTED"}]}},
		{"number": 4, "createdAt": "2026-01-04", "author": {"login": "me"}, "reviews": {"nodes": [
			{"author": {"login": "a"}, "authorAssociation": "MEMBER", "state": "APPROVED"},
			{"author": {"login": "b"}, "authorAssociation": "COLLABORATOR", "state": "CHANGES_REQUESTED"}]},
		 "reviewRequests": {"nodes": [{"requestedReviewer": {"login": "b"}}]}},
		{"number": 5, "createdAt": "2026-01-05", "author": {"login": "me"}, "reviews": {"nodes": [
			{"author": {"login": "a"}, "authorAssociation": "OWNER", "state": "COMMENTED"}]},
		 "reviewRequests": {"nodes": [{"requestedReviewer": {"login": "c"}}]}},
		{"number": 6, "createdAt": "2026-01-06", "author": {"login": "me"}, "reviews": {"nodes": [
			{"author": {"login": "a"}, "authorAssociation": "MEMBER", "state": "DISMISSED"}]}},
		{"number": 7, "createdAt": "2026-01-07", "author": {"login": "me"}, "reviews": {"nodes": [
			{"author": {"login": "a"}, "authorAssociation": "MEMBER", "state": "CHANGES_REQUESTED"},
			{"author": {"login": "a"}, "authorAssociation": "MEMBER", "state": "APPROVED"}]}},
		{"number": 8, "createdAt": "2026-01-08", "author": {"login": "me"}, "reviews": {"nodes": [
			{"author": {"login": "a"}, "authorAssociation": "MEMBER", "state": "APPROVED"},
			{"author": {"login": "a"}, "authorAssociation": "MEMBER", "state": "CHANGES_REQUESTED"}]}}]`)
	for i := range prs {
		prs[i].Title, prs[i].UpdatedAt, prs[i].HeadRefName = "t", "u", fmt.Sprintf("b%d", prs[i].Number)
	}
	if err := writeCache("prs", prCacheLines(prs)); err != nil {
		t.Fatal(err)
	}
	var got [][2]string
	for _, line := range cmdLines([]string{"pr"}) {
		f := strings.Split(line, "\t")
		if len(f[3]) < 300 {
			t.Errorf("not padded, so tags don't sit flush right: %q", f[3])
		}
		got = append(got, [2]string{strings.TrimRight(ansi.ReplaceAllString(f[3], ""), " "), strings.TrimSpace(ansi.ReplaceAllString(f[4], ""))})
	}
	want := [][2]string{
		{"#8  t  @me", "[changes requested]"},
		{"#7  t  @me", "[approved]"},
		{"#6  t  @me", "[commented]"},
		{"#5  t  @me", "[commented]"},
		{"#4  t  @me", "[re-review] [changes requested]"},
		{"#3  t  @me", "[approved]"},
		{"#2  t  @me", "[unreviewed]"},
		{"#1  t  @app/dependabot", "[unreviewed]"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

// tmux's arguments, as they were before wt supported other multiplexers

func (f *fixture) switchFeature() string {
	f.t.Helper()
	f.git("branch", "feature/x.y")
	if err := switchToBranch("feature/x.y"); err != nil {
		f.t.Fatal(err, f.stderr.String())
	}
	return filepath.Join(f.repo, "feature/x.y")
}

func (f *fixture) clone() string {
	f.t.Helper()
	f.t.Chdir(f.root)
	if err := cmdClone(f.remote, "cloned"); err != nil {
		f.t.Fatal(err, f.stderr.String())
	}
	return filepath.Join(f.root, "cloned/main")
}

func checkCalls(t *testing.T, got, want [][]string) {
	t.Helper()
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("calls %q\nwant %q", got, want)
	}
}

func TestSwitchOutsideTmuxAttaches(t *testing.T) {
	f := setup(t)
	path := f.switchFeature()
	checkCalls(t, f.calls(), [][]string{{"tmux", "new-session", "-A", "-s", "feature_x_y", "-c", path}})
}

func TestSwitchInsideTmuxCreatesAndSwitches(t *testing.T) {
	f := setup(t)
	t.Setenv("TMUX", "/tmp/tmux-test,1,0")
	path := f.switchFeature()
	checkCalls(t, f.calls(), [][]string{
		{"tmux", "has-session", "-t", "=feature_x_y"},
		{"tmux", "new-session", "-d", "-s", "feature_x_y", "-c", path},
		{"tmux", "switch-client", "-t", "=feature_x_y"},
	})
}

func TestSwitchInsideTmuxReusesSession(t *testing.T) {
	f := setup(t)
	t.Setenv("TMUX", "/tmp/tmux-test,1,0")
	f.stub("tmux-has-session", "")
	f.switchFeature()
	checkCalls(t, f.calls(), [][]string{
		{"tmux", "has-session", "-t", "=feature_x_y"},
		{"tmux", "switch-client", "-t", "=feature_x_y"},
	})
}

func TestCloneOutsideTmuxAttaches(t *testing.T) {
	f := setup(t)
	path := f.clone()
	checkCalls(t, f.calls(), [][]string{{"tmux", "new-session", "-A", "-s", "main", "-c", path}})
}

func TestCloneInsideTmuxCreatesAndSwitches(t *testing.T) {
	f := setup(t)
	t.Setenv("TMUX", "/tmp/tmux-test,1,0")
	path := f.clone()
	checkCalls(t, f.calls(), [][]string{
		{"tmux", "has-session", "-t", "=main"},
		{"tmux", "new-session", "-d", "-s", "main", "-c", path},
		{"tmux", "switch-client", "-t", "=main"},
	})
}

// Multiplexer selection

var (
	inTmux = map[string]string{"TMUX": "/tmp/tmux-test,1,0"}
	inRex  = map[string]string{"REX_SESSION": rexWhoamiLive["session_id"].(string)}
)

func setenv(t *testing.T, envs ...map[string]string) {
	for _, env := range envs {
		for k, v := range env {
			t.Setenv(k, v)
		}
	}
}

// picked is the multiplexer muxPreflight picks, or its error.
func (f *fixture) picked(whoami map[string]any) string {
	f.stub("whoami.json", whoami)
	mux = ""
	f.stderr.Reset()
	if err := muxPreflight(); err != nil {
		return f.stderr.String()
	}
	return mux
}

func TestAutoSelection(t *testing.T) {
	f := setup(t)
	for _, c := range []struct {
		name   string
		env    []map[string]string
		whoami map[string]any
		want   string
	}{
		{"unset, no context", nil, rexWhoamiLive, "tmux"},
		{"auto, no context", []map[string]string{{"WT_MULTIPLEXER": "auto"}}, rexWhoamiLive, "tmux"},
		{"tmux", []map[string]string{inTmux}, rexWhoamiLive, "tmux"},
		{"live Rex", []map[string]string{inRex}, rexWhoamiLive, "rex"},
		{"stale Rex", []map[string]string{inRex}, rexWhoamiStale, "tmux"},
		{"tmux inside Rex", []map[string]string{inTmux, inRex}, rexWhoamiLive, "tmux"},
	} {
		t.Run(c.name, func(t *testing.T) {
			setenv(t, c.env...)
			if got := f.picked(c.whoami); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
	// Confirming a stale REX_SESSION must never start a Rex server
	var whoami [][]string
	for _, call := range f.calls() {
		if slices.Contains(call, "whoami") {
			whoami = append(whoami, call)
		}
	}
	if len(whoami) == 0 || slices.ContainsFunc(whoami, func(c []string) bool { return c[1] != "--autostart=false" }) {
		t.Errorf("whoami calls %q", whoami)
	}
}

func TestExplicitSelectionWins(t *testing.T) {
	f := setup(t)
	for _, c := range []struct {
		name string
		env  []map[string]string
		want string
	}{
		{"tmux inside Rex", []map[string]string{inRex, {"WT_MULTIPLEXER": "tmux"}}, "tmux"},
		{"Rex inside tmux", []map[string]string{inTmux, {"WT_MULTIPLEXER": "rex"}}, "rex"},
		{"Rex outside Rex", []map[string]string{{"WT_MULTIPLEXER": "rex"}}, "rex"},
	} {
		t.Run(c.name, func(t *testing.T) {
			setenv(t, c.env...)
			if got := f.picked(rexWhoamiLive); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestInvalidSettingFails(t *testing.T) {
	f := setup(t)
	t.Setenv("WT_MULTIPLEXER", "screen")
	if got := f.picked(rexWhoamiLive); !strings.Contains(got, "WT_MULTIPLEXER must be auto, tmux or rex, not 'screen'") {
		t.Errorf("got %q", got)
	}
	checkCalls(t, f.calls(), nil)
}

func TestRexFailureNeverFallsBackOrMemoizes(t *testing.T) {
	f := setup(t)
	setenv(t, inTmux, map[string]string{"WT_MULTIPLEXER": "rex"})
	f.stub("client-error", "Error: rex server is not running\n")
	for range 2 {
		if muxPreflight() == nil || mux != "" {
			t.Fatalf("picked %q", mux)
		}
	}
	if !strings.Contains(f.stderr.String(), "rex server is not running") {
		t.Errorf("stderr %q", f.stderr.String())
	}
	// Inside tmux, the error is also shown on its status line, but no tmux session is opened
	var tmux [][]string
	for _, call := range f.calls() {
		if call[0] == "tmux" {
			tmux = append(tmux, call[:2])
		}
	}
	checkCalls(t, tmux, [][]string{{"tmux", "display-message"}, {"tmux", "display-message"}})
}

// A multiplexer that can't open the worktree fails before wt changes anything.

func (f *fixture) checkPreflight(run func() error, mutated func() bool) {
	noSelect := map[string]any{"actions": []any{rexInspect["actions"].([]any)[0]}}
	for _, c := range []struct {
		name    string
		env     map[string]string
		stub    []any
		message string
	}{
		{"invalid setting", map[string]string{"WT_MULTIPLEXER": "bogus"}, nil, "WT_MULTIPLEXER must be"},
		{"tmux missing", map[string]string{"WT_MULTIPLEXER": "tmux", "PATH": f.pathWithout("tmux")}, nil, "tmux not found"},
		{"rex missing", map[string]string{"WT_MULTIPLEXER": "rex", "PATH": f.pathWithout("rex")}, nil, "needs rex"},
		{"server down", map[string]string{"WT_MULTIPLEXER": "rex"}, []any{"client-error", "Error: rex server is not running\n"},
			"rex server is not running"},
		{"ambiguous apps", map[string]string{"WT_MULTIPLEXER": "rex"},
			[]any{"client-error", "Error: 2 app clients are connected; choose one with -C\n"}, "REX_CLIENT"},
		{"no session.select", map[string]string{"WT_MULTIPLEXER": "rex"}, []any{"inspect.json", noSelect}, "no session.select"},
	} {
		f.t.Run(c.name, func(t *testing.T) {
			f.resetStubs()
			mux = ""
			f.stderr.Reset()
			if c.stub != nil {
				f.stub(c.stub[0].(string), c.stub[1])
			}
			setenv(t, c.env)
			if run() == nil {
				t.Fatal("succeeded")
			}
			if !strings.Contains(f.stderr.String(), c.message) {
				t.Errorf("stderr %q", f.stderr.String())
			}
			if mutated() {
				t.Error("changed the repository")
			}
			for _, call := range f.calls() {
				if call[0] == "tmux" || slices.Equal(call[:2], []string{"rex", "new"}) || slices.Equal(call[:2], []string{"rex", "do"}) {
					t.Errorf("called %q", call)
				}
			}
		})
	}
}

func TestPreflightSwitch(t *testing.T) {
	f := setup(t)
	f.checkPreflight(func() error { return switchToBranch("new-branch") },
		func() bool { return f.hasRef("refs/heads/new-branch") || exists(filepath.Join(f.repo, "new-branch")) })
}

func TestPreflightClone(t *testing.T) {
	f := setup(t)
	t.Chdir(f.root)
	f.checkPreflight(func() error { return cmdClone(f.remote, "cloned") },
		func() bool { return exists(filepath.Join(f.root, "cloned")) })
}

func TestPreflightPR(t *testing.T) {
	f := setup(t)
	f.remoteBranch("pr-branch")
	f.git("update-ref", "-d", "refs/remotes/origin/pr-branch")
	if err := writeCache("prs", []string{"7\t2026-01-01T00:00:00Z\tfalse\tfalse\tpr-branch\tTitle\tme\t"}); err != nil {
		t.Fatal(err)
	}
	f.checkPreflight(func() error { return openPR("7") },
		func() bool { return f.hasRef("refs/heads/pr-branch") || f.hasRef("refs/remotes/origin/pr-branch") })
}

// Commands that don't open a worktree never need, or touch, a multiplexer.

func TestHelpersWorkWithoutMultiplexers(t *testing.T) {
	f := setup(t)
	setenv(t, map[string]string{"PATH": f.pathWithout("tmux", "rex"), "WT_MULTIPLEXER": "bogus"})
	for _, args := range [][]string{{"--list-branches"}, {"--header"}, {"--lines", "issue"}, {"list"}, {"--help"}} {
		if _, stderr, ok := f.wt(args...); !ok {
			t.Errorf("%q failed: %s", args, stderr)
		}
	}
	if help, _, _ := f.wt("--help"); !strings.Contains(help, "WT_MULTIPLEXER") {
		t.Error("help doesn't describe WT_MULTIPLEXER")
	}
}

func TestDeletionNeverCallsAMultiplexer(t *testing.T) {
	f := setup(t)
	setenv(t, inTmux, inRex)
	for _, branch := range []string{"gone", "gone-too"} {
		f.git("worktree", "add", "-q", "-b", branch, filepath.Join(f.root, branch))
	}
	f.deleteSelected("refs/heads/gone", "gone [wt]", "Cancel")
	pick = func(input []string, _ ...string) ([]string, int) {
		for _, line := range input {
			if strings.Contains(line, "gone-too") {
				return []string{line}, 0
			}
		}
		return nil, 1
	}
	if err := cmdDelete(strings.NewReader("y\n")); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	if exists(filepath.Join(f.root, "gone")) || exists(filepath.Join(f.root, "gone-too")) {
		t.Error("worktree left")
	}
	checkCalls(t, f.calls(), nil)
}

func TestCancelledPickersAreNoOps(t *testing.T) {
	f := setup(t)
	if err := writeCache("issues", []string{"5\t2026-01-01T00:00:00Z\tAn issue\t"}); err != nil {
		t.Fatal(err)
	}
	setenv(t, map[string]string{"PATH": f.pathWithout("rex"), "WT_MULTIPLEXER": "rex"})
	f.picks(nil, 130)
	for name, run := range map[string]func() error{
		"switch":          cmdSwitch,
		"issues":          func() error { return cmdGitHub("issue") },
		"issue's branch":  func() error { return openIssue("5") },
		"no branch given": func() error { return switchToBranch("") },
	} {
		if err := run(); err != nil {
			t.Errorf("%s: %v %s", name, err, f.stderr.String())
		}
	}
	checkCalls(t, f.calls(), nil)
}

func TestInvalidSettingFailsBeforePickers(t *testing.T) {
	f := setup(t)
	t.Setenv("WT_MULTIPLEXER", "bogus")
	f.picks(nil, 0)
	for name, run := range map[string]func() error{"switch": cmdSwitch, "issues": func() error { return cmdGitHub("issue") }} {
		f.stderr.Reset()
		if run() == nil || !strings.Contains(f.stderr.String(), "WT_MULTIPLEXER must be") {
			t.Errorf("%s: %q", name, f.stderr.String())
		}
	}
	if f.pickerShown {
		t.Error("picker shown")
	}
}

// Rex

func (f *fixture) rexSwitch(branch string) error {
	t := f.t
	t.Setenv("WT_MULTIPLEXER", "rex")
	mux = ""
	f.stderr.Reset()
	return switchToBranch(branch)
}

func (f *fixture) rexCalls() [][]string {
	var calls [][]string
	for _, call := range f.calls() {
		if call[0] == "rex" && !slices.Equal(call[1:3], []string{"--autostart=false", "client"}) {
			calls = append(calls, call[1:])
		}
	}
	return calls
}

func (f *fixture) clearCalls() {
	os.Remove(filepath.Join(f.stubState, "calls"))
}

func session(n int) string {
	return fmt.Sprintf("session:01a1801a-0000-7000-8000-%012d", n)
}

func rexFixture(t *testing.T) (*fixture, string, string) {
	f := setup(t)
	worktree := filepath.Join(f.repo, "feature/x.y")
	return f, worktree, "repo-feature_x.y-" + gitHash(worktree)[:10]
}

func TestRexCreatesSessionThenReusesIt(t *testing.T) {
	f, worktree, label := rexFixture(t)
	if err := f.rexSwitch("feature/x.y"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.rexCalls(), [][]string{
		{"ls", "--json"},
		{"new", label, "-c", worktree, "--json"},
		{"do", "session.select", "session_id=" + session(0)},
	})
	f.clearCalls()
	if err := f.rexSwitch("feature/x.y"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.rexCalls(), [][]string{{"ls", "--json"}, {"do", "session.select", "session_id=" + session(0)}})
}

func TestRexSymlinkedPathReusesSession(t *testing.T) {
	f, worktree, _ := rexFixture(t)
	f.rexSwitch("feature/x.y")
	alias := filepath.Join(f.root, "alias")
	if err := os.Symlink(worktree, alias); err != nil {
		t.Fatal(err)
	}
	f.clearCalls()
	if err := muxOpenWorktree(alias, "feature/x.y"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.rexCalls(), [][]string{{"ls", "--json"}, {"do", "session.select", "session_id=" + session(0)}})
}

func TestRexPrefixMatchesAreNotReused(t *testing.T) {
	f, worktree, label := rexFixture(t)
	f.stub("sessions.json", []map[string]string{
		{"session_id": "session:prefix", "label": label[:len(label)-1]},
		{"session_id": "session:longer", "label": label + "-2"},
		{"session_id": "session:no-hash", "label": "repo-feature_x.y"},
	})
	if err := f.rexSwitch("feature/x.y"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	calls := f.rexCalls()
	if !slices.ContainsFunc(calls, func(c []string) bool { return slices.Equal(c, []string{"new", label, "-c", worktree, "--json"}) }) ||
		!slices.Equal(calls[len(calls)-1], []string{"do", "session.select", "session_id=" + session(3)}) {
		t.Errorf("calls %q", calls)
	}
}

func TestRexDuplicateLabelsFail(t *testing.T) {
	f, worktree, label := rexFixture(t)
	f.stub("sessions.json", []map[string]string{{"session_id": "session:a", "label": label}, {"session_id": "session:b", "label": label}})
	if f.rexSwitch("feature/x.y") == nil {
		t.Fatal("succeeded")
	}
	want := fmt.Sprintf("wt: worktree ready at %s; Rex session could not be opened: several sessions are labelled %s: session:a, session:b", worktree, label)
	if !strings.Contains(f.stderr.String(), want) {
		t.Errorf("stderr %q", f.stderr.String())
	}
	checkCalls(t, f.rexCalls(), [][]string{{"ls", "--json"}})
	if !exists(worktree) {
		t.Error("worktree removed")
	}
}

func TestRexUncertainCreationReusesCreatedSession(t *testing.T) {
	f, worktree, label := rexFixture(t)
	f.stub("new-error", "Error: timed out\n")
	if err := f.rexSwitch("feature/x.y"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.rexCalls(), [][]string{
		{"ls", "--json"},
		{"new", label, "-c", worktree, "--json"},
		{"ls", "--json"},
		{"do", "session.select", "session_id=" + session(0)},
	})
}

func TestRexActivationFailureKeepsWorktree(t *testing.T) {
	f, worktree, _ := rexFixture(t)
	f.stub("do-error", "Error: The operation couldn't be completed.\n")
	if f.rexSwitch("feature/x.y") == nil {
		t.Fatal("succeeded")
	}
	want := fmt.Sprintf("wt: worktree ready at %s; Rex session could not be opened: can't show session %s: Error: The operation", worktree, session(0))
	if !strings.Contains(f.stderr.String(), want) {
		t.Errorf("stderr %q", f.stderr.String())
	}
	if !exists(worktree) || !f.hasRef("refs/heads/feature/x.y") {
		t.Error("worktree or branch removed")
	}
}

func TestRexQuotesPathsWithSpaces(t *testing.T) {
	f := setup(t)
	worktree := filepath.Join(f.root, "dir with space/feature.a")
	f.git("worktree", "add", "-q", "-b", "feature/a.b", worktree)
	if err := f.rexSwitch("feature/a.b"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	want := []string{"new", "repo-feature_a.b-" + gitHash(worktree)[:10], "-c", worktree, "--json"}
	if calls := f.rexCalls(); !slices.ContainsFunc(calls, func(c []string) bool { return slices.Equal(c, want) }) {
		t.Errorf("calls %q", calls)
	}
}

func TestRexLabels(t *testing.T) {
	f := setup(t)
	a, b := filepath.Join(f.root, "a/app"), filepath.Join(f.root, "b/app")
	for _, repo := range []string{a, b} {
		f.run("git", "init", "-q", "-b", "main", repo)
	}
	if got, want := rexLabel(a, "main"), "app-main-"+gitHash(a)[:10]; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if rexLabel(a, "main") == rexLabel(b, "main") {
		t.Error("same label for two repositories")
	}
	long := rexLabel(a, strings.Repeat("x", 200))
	if len(long) != 111 || !strings.HasSuffix(long, "-"+gitHash(a)[:10]) {
		t.Errorf("long label %q", long)
	}
}
