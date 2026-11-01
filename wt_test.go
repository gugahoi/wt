package main

import (
	"bytes"
	"cmp"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	fzf "github.com/junegunn/fzf/src"
)

// The test binary also stands in for tmux, zellij and rex, and for wt itself when wt runs itself in the
// background: they are stubs on PATH that log their arguments, and files in $WT_STUB_DIR change their
// answers. rex's exit codes are the real ones. No network, tmux, Zellij or Rex needed.
func TestMain(m *testing.M) {
	if name := filepath.Base(os.Args[0]); name == "tmux" || name == "zellij" || name == "rex" {
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
	// windows.json records each window rex opens, as {"session_id", "window_id"}.
	appendWindow := func(sessionID string) string {
		windows := read("windows.json", []any{}).([]any)
		id := windowID(len(windows))
		data, _ := json.Marshal(append(windows, map[string]any{"session_id": sessionID, "window_id": id}))
		os.WriteFile(filepath.Join(state, "windows.json"), data, 0o644)
		return id
	}

	if name == "tmux" {
		switch args[0] {
		case "has-session":
			if _, err := os.Stat(filepath.Join(state, "tmux-has-session")); err != nil {
				return 1
			}
		case "new-session":
			fail("new-error", 1)
		case "new-window":
			fail("window-error", 1)
		}
		return 0
	}
	if name == "zellij" {
		// zellij --session <name> action ...: the session an action goes to
		target := ""
		if args[0] == "--session" {
			target, args = args[1], args[2:]
		}
		// zellij-client names the session the client is showing, which attaching or switching to it sets, unless
		// zellij-no-client says no client ever connects
		connect := func(session string) {
			if _, err := os.Stat(filepath.Join(state, "zellij-no-client")); err != nil {
				os.WriteFile(filepath.Join(state, "zellij-client"), []byte(session), 0o644)
			}
		}
		switch args[0] {
		case "--version":
			version, err := os.ReadFile(filepath.Join(state, "zellij-version"))
			if err != nil {
				version = []byte("zellij 0.45.1\n")
			}
			os.Stdout.Write(version)
		case "list-sessions":
			// zellij-sessions lists them; with none, zellij says so and exits 1, as it does when it fails
			fail("zellij-list-error", 2)
			names, _ := os.ReadFile(filepath.Join(state, "zellij-sessions"))
			if len(names) == 0 {
				fmt.Fprintln(os.Stderr, "No active zellij sessions found.")
				return 1
			}
			os.Stdout.Write(names)
		case "attach":
			dir, _ := os.Getwd()
			os.WriteFile(filepath.Join(state, "zellij-cwd"), []byte(dir), 0o644)
			fail("zellij-error", 1)
			if args[1] != "--create-background" {
				connect(args[2])
			}
		case "action":
			fail("zellij-error", 1)
			client, _ := os.ReadFile(filepath.Join(state, "zellij-client"))
			switch args[1] {
			case "switch-session":
				connect(args[2])
			case "list-clients":
				fmt.Println("CLIENT_ID ZELLIJ_PANE_ID RUNNING_COMMAND")
				if string(client) == target {
					fmt.Println("1         terminal_0     N/A")
				}
			case "new-tab":
				// a tab needs a client to show it, and to size it
				if string(client) != target {
					fmt.Fprintln(os.Stderr, "Failed to apply layout: Not enough room for panes")
					return 1
				}
				fail("zellij-tab-error", 1)
				fmt.Println(1)
			}
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
		id := session(len(sessions))
		data, _ := json.Marshal(append(sessions, map[string]any{"session_id": id, "label": args[1]}))
		os.WriteFile(filepath.Join(state, "sessions.json"), data, 0o644)
		initial := appendWindow(id)
		fail("new-error", 1)
		print(map[string]any{"session_id": id, "initial_windows": []any{
			map[string]any{"window_id": initial, "block_ids": []any{}, "revision": 1}}})
	case "window": // window new -s <session> ...
		fail("window-error", 1)
		id := appendWindow(args[3])
		// fails, or answers window-output, once the window is open
		fail("window-error-after", 1)
		if data, err := os.ReadFile(filepath.Join(state, "window-output")); err == nil {
			os.Stdout.Write(data)
		} else {
			print(map[string]any{"window_id": id, "block_ids": []any{}})
		}
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
	answers            []pickAnswer
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
	for _, name := range []string{"tmux", "zellij", "rex"} {
		if err := os.Symlink(exe, filepath.Join(f.stubs, name)); err != nil {
			t.Fatal(err)
		}
	}
	// Inherited from the terminal running the tests, these would point wt at a live tmux, Zellij or Rex.
	for _, name := range []string{"TMUX", "TMUX_PANE", "ZELLIJ", "ZELLIJ_SESSION_NAME", "ZELLIJ_PANE_ID", "REX_SESSION",
		"REX_BLOCK", "REX_CLIENT", "WT_MULTIPLEXER", "WT_OPEN_COMMAND", "WT_REFRESHED", "FZF_PROMPT"} {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
	// Where Zellij keeps its sockets decides how long its session labels can be: this short folder leaves the
	// usual 24 bytes, whoever runs the tests and wherever their temp folder is.
	t.Setenv("ZELLIJ_SOCKET_DIR", "/tmp/zellij")
	t.Setenv("WT_STUB_DIR", f.stubState)
	// wt reads the user's command configuration from here, never from the developer's.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
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

	mux = nil
	errOut = &f.stderr
	pick = func(input []string, args ...string) ([]string, int) {
		t.Fatalf("unexpected picker %q", args)
		return nil, 0
	}
	t.Cleanup(func() { mux, errOut, pick = nil, os.Stderr, runFzf })
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

type pickAnswer struct {
	out  []string
	code int
}

// answer makes the next pickers answer in turn, recording that they were shown. Pickers beyond the answers
// fail the test; f.answers holds those left unused.
func (f *fixture) answer(answers ...pickAnswer) {
	f.answers = answers
	pick = func(_ []string, args ...string) ([]string, int) {
		f.pickerShown = true
		if len(f.answers) == 0 {
			f.t.Fatalf("unexpected picker %q", args)
		}
		a := f.answers[0]
		f.answers = f.answers[1:]
		return a.out, a.code
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

// pathWithout is a PATH with git, sh and the multiplexer stubs, except those missing.
func (f *fixture) pathWithout(missing ...string) string {
	dir := filepath.Join(f.root, "path-without-"+strings.Join(missing, "-"))
	if _, err := os.Stat(dir); err == nil {
		return dir
	}
	os.Mkdir(dir, 0o755)
	for _, name := range []string{"git", "sh", "tmux", "zellij", "rex"} {
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
	if err := switchToBranch("upstream/123-topic\t"+strings.Join(row, "\t"), ""); err != nil {
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

// A missing branch marker must still leave a non-whitespace right field for --freeze-right=1.
// Otherwise fzf trims that field away and clips the beginning of a long issue title.
func TestIssueRowsKeepTitleStartAndRightMarker(t *testing.T) {
	f := setup(t)
	f.git("branch", "2-topic")
	f.git("worktree", "add", "-q", "-b", "3-topic", filepath.Join(f.root, "3-topic"))
	title := strings.Repeat("Long issue title ", 12)
	if err := writeCache("issues", []string{
		"1\t2026-01-01\t" + title + "\tmaintenance",
		"2\t2026-01-02\t" + title + "\t",
		"3\t2026-01-03\t" + title + "\t",
	}); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"1": "·", "2": "[br]", "3": "[wt]"}
	rows := issueLines()
	if len(rows) != len(want) {
		t.Fatalf("got %d issue rows, want %d", len(rows), len(want))
	}
	for _, row := range rows {
		fields := strings.Split(row, "\t")
		if len(fields) != 5 || fields[0] != "issue" {
			t.Fatalf("bad issue row %q", row)
		}
		number := fields[1]
		if !strings.HasPrefix(fields[3], "#"+number+"  "+title) || len(fields[3]) < 300 {
			t.Errorf("issue %s lost its title prefix or padding: %q", number, fields[3])
		}
		// Simulate fzf's ANSI and trailing-whitespace removal: the right field must survive.
		shown := strings.TrimRight(ansi.ReplaceAllString(strings.Join(fields[3:], "\t"), ""), " \t")
		visible := strings.Split(shown, "\t")
		if len(visible) != 2 || strings.TrimSpace(visible[1]) != want[number] {
			t.Errorf("issue %s right field: %q, want %q", number, shown, want[number])
		}
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
	if err := switchToBranch("feature/x.y", ""); err != nil {
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
	inTmux   = map[string]string{"TMUX": "/tmp/tmux-test,1,0"}
	inZellij = map[string]string{"ZELLIJ": "0", "ZELLIJ_SESSION_NAME": "current"}
	inRex    = map[string]string{"REX_SESSION": rexWhoamiLive["session_id"].(string)}
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
	mux = nil
	f.stderr.Reset()
	if err := muxPreflight(); err != nil {
		return f.stderr.String()
	}
	return mux.name
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
		{"Zellij", []map[string]string{inZellij}, rexWhoamiLive, "zellij"},
		{"Zellij inside Rex", []map[string]string{inZellij, inRex}, rexWhoamiLive, "zellij"},
		{"tmux and Zellij", []map[string]string{inTmux, inZellij}, rexWhoamiLive, "tmux"},
		{"WT_OPEN_COMMAND alone", []map[string]string{{"WT_OPEN_COMMAND": "true"}}, rexWhoamiLive, "tmux"},
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
		{"Zellij inside tmux", []map[string]string{inTmux, {"WT_MULTIPLEXER": "zellij"}}, "zellij"},
		{"command inside Zellij", []map[string]string{inZellij, {"WT_MULTIPLEXER": "command", "WT_OPEN_COMMAND": "true"}}, "command"},
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
	if got := f.picked(rexWhoamiLive); !strings.Contains(got, "WT_MULTIPLEXER must be auto, tmux, zellij, rex or command, not 'screen'") {
		t.Errorf("got %q", got)
	}
	checkCalls(t, f.calls(), nil)
}

func TestRexFailureNeverFallsBackOrMemoizes(t *testing.T) {
	f := setup(t)
	setenv(t, inTmux, map[string]string{"WT_MULTIPLEXER": "rex"})
	f.stub("client-error", "Error: rex server is not running\n")
	for range 2 {
		if muxPreflight() == nil || mux != nil {
			t.Fatalf("picked %v", mux)
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
	// One byte less than a label needs to keep a whole character of its name before the hash
	noRoom := socketDirLeaving(labelSuffixSize + utf8.UTFMax - 1)
	tooLong := "Zellij's socket folder " + noRoom + "/contract_version_1 is too long for session names: set a shorter ZELLIJ_SOCKET_DIR"
	for _, c := range []struct {
		name    string
		env     map[string]string
		stub    []any
		message string
	}{
		{"invalid setting", map[string]string{"WT_MULTIPLEXER": "bogus"}, nil, "WT_MULTIPLEXER must be"},
		{"tmux missing", map[string]string{"WT_MULTIPLEXER": "tmux", "PATH": f.pathWithout("tmux")}, nil, "tmux not found"},
		{"zellij missing", map[string]string{"WT_MULTIPLEXER": "zellij", "PATH": f.pathWithout("zellij")}, nil, "zellij not found"},
		{"Zellij can't switch sessions", map[string]string{"WT_MULTIPLEXER": "zellij", "ZELLIJ": "0"},
			[]any{"zellij-version", "zellij 0.43.1\n"}, "needs zellij 0.44 or later, not 'zellij 0.43.1'"},
		{"Zellij version with a negative major", map[string]string{"WT_MULTIPLEXER": "zellij", "ZELLIJ": "0"},
			[]any{"zellij-version", "zellij -1.0\n"}, "needs zellij 0.44 or later, not 'zellij -1.0'"},
		{"Zellij version with a negative minor", map[string]string{"WT_MULTIPLEXER": "zellij", "ZELLIJ": "0"},
			[]any{"zellij-version", "zellij 1.-1\n"}, "needs zellij 0.44 or later, not 'zellij 1.-1'"},
		{"Zellij version with a sign", map[string]string{"WT_MULTIPLEXER": "zellij", "ZELLIJ": "0"},
			[]any{"zellij-version", "zellij +1.0\n"}, "needs zellij 0.44 or later, not 'zellij +1.0'"},
		{"Zellij socket folder too long", map[string]string{"WT_MULTIPLEXER": "zellij", "ZELLIJ_SOCKET_DIR": noRoom}, nil, tooLong},
		{"Zellij socket folder too long inside Zellij",
			map[string]string{"WT_MULTIPLEXER": "zellij", "ZELLIJ": "0", "ZELLIJ_SOCKET_DIR": noRoom}, nil, tooLong},
		{"rex missing", map[string]string{"WT_MULTIPLEXER": "rex", "PATH": f.pathWithout("rex")}, nil, "needs rex"},
		{"server down", map[string]string{"WT_MULTIPLEXER": "rex"}, []any{"client-error", "Error: rex server is not running\n"},
			"rex server is not running"},
		{"ambiguous apps", map[string]string{"WT_MULTIPLEXER": "rex"},
			[]any{"client-error", "Error: 2 app clients are connected; choose one with -C\n"}, "REX_CLIENT"},
		{"no session.select", map[string]string{"WT_MULTIPLEXER": "rex"}, []any{"inspect.json", noSelect}, "no session.select"},
		{"no command", map[string]string{"WT_MULTIPLEXER": "command"}, nil, "needs WT_OPEN_COMMAND"},
	} {
		f.t.Run(c.name, func(t *testing.T) {
			f.resetStubs()
			mux = nil
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
				if call[0] == "tmux" || call[0] == "zellij" && call[1] != "--version" ||
					slices.Equal(call[:2], []string{"rex", "new"}) || slices.Equal(call[:2], []string{"rex", "do"}) {
					t.Errorf("called %q", call)
				}
			}
		})
	}
}

func TestPreflightSwitch(t *testing.T) {
	f := setup(t)
	f.checkPreflight(func() error { return switchToBranch("new-branch", "") },
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
	f.checkPreflight(func() error { return openPR("7", "") },
		func() bool { return f.hasRef("refs/heads/pr-branch") || f.hasRef("refs/remotes/origin/pr-branch") })
}

// Commands that don't open a worktree never need, or touch, a multiplexer.

func TestHelpersWorkWithoutMultiplexers(t *testing.T) {
	f := setup(t)
	setenv(t, map[string]string{"PATH": f.pathWithout("tmux", "zellij", "rex"), "WT_MULTIPLEXER": "bogus"})
	for _, args := range [][]string{{"--list-branches"}, {"--header"}, {"--lines", "issue"}, {"list"}, {"--help"}} {
		if _, stderr, ok := f.wt(args...); !ok {
			t.Errorf("%q failed: %s", args, stderr)
		}
	}
}

func TestDeletionNeverCallsAMultiplexer(t *testing.T) {
	f := setup(t)
	setenv(t, inTmux, inZellij, inRex)
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
		"issue's branch":  func() error { return openIssue("5", commandConfig{}, "") },
		"no branch given": func() error { return switchToBranch("", "") },
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

// switchIn switches to branch as wt does with WT_MULTIPLEXER=name.
func (f *fixture) switchIn(name, branch string) error {
	return f.launchIn(name, branch, "")
}

// launchIn switches to branch as wt does with WT_MULTIPLEXER=name, opening command rather than a shell.
func (f *fixture) launchIn(name, branch, command string) error {
	f.t.Setenv("WT_MULTIPLEXER", name)
	mux = nil
	f.stderr.Reset()
	return switchToBranch(branch, command)
}

// Rex

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

func windowID(n int) string {
	return fmt.Sprintf("window:01a1801a-0000-7000-8000-%012d", n)
}

type rexWindow struct {
	SessionID string `json:"session_id"`
	WindowID  string `json:"window_id"`
}

// windows are the windows rex has opened, in order.
func (f *fixture) windows() []rexWindow {
	data, err := os.ReadFile(filepath.Join(f.stubState, "windows.json"))
	if err != nil {
		return nil
	}
	var windows []rexWindow
	if err := json.Unmarshal(data, &windows); err != nil {
		f.t.Fatal(err)
	}
	return windows
}

// sessionIDs are the IDs of rex's sessions, in order.
func (f *fixture) sessionIDs() []string {
	data, err := os.ReadFile(filepath.Join(f.stubState, "sessions.json"))
	if err != nil {
		return nil
	}
	var sessions []struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(data, &sessions); err != nil {
		f.t.Fatal(err)
	}
	var ids []string
	for _, s := range sessions {
		ids = append(ids, s.SessionID)
	}
	return ids
}

func rexFixture(t *testing.T) (*fixture, string, string) {
	f := setup(t)
	worktree := filepath.Join(f.repo, "feature/x.y")
	return f, worktree, "repo-feature_x.y-" + gitHash(worktree)[:10]
}

func TestRexCreatesSessionThenReusesIt(t *testing.T) {
	f, worktree, label := rexFixture(t)
	if err := f.switchIn("rex", "feature/x.y"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.rexCalls(), [][]string{
		{"ls", "--json"},
		{"new", label, "-c", worktree, "--json"},
		{"do", "session.select", "session_id=" + session(0)},
	})
	f.clearCalls()
	if err := f.switchIn("rex", "feature/x.y"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.rexCalls(), [][]string{{"ls", "--json"}, {"do", "session.select", "session_id=" + session(0)}})
}

func TestRexSymlinkedPathReusesSession(t *testing.T) {
	f, worktree, _ := rexFixture(t)
	f.switchIn("rex", "feature/x.y")
	alias := filepath.Join(f.root, "alias")
	if err := os.Symlink(worktree, alias); err != nil {
		t.Fatal(err)
	}
	f.clearCalls()
	if err := muxOpenWorktree(alias, "feature/x.y", ""); err != nil {
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
	if err := f.switchIn("rex", "feature/x.y"); err != nil {
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
	if f.switchIn("rex", "feature/x.y") == nil {
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
	if err := f.switchIn("rex", "feature/x.y"); err != nil {
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
	if f.switchIn("rex", "feature/x.y") == nil {
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
	if err := f.switchIn("rex", "feature/a.b"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	want := []string{"new", "repo-feature_a.b-" + gitHash(worktree)[:10], "-c", worktree, "--json"}
	if calls := f.rexCalls(); !slices.ContainsFunc(calls, func(c []string) bool { return slices.Equal(c, want) }) {
		t.Errorf("calls %q", calls)
	}
}

func TestSessionLabels(t *testing.T) {
	f := setup(t)
	a, b := filepath.Join(f.root, "a/app"), filepath.Join(f.root, "b/app")
	for _, repo := range []string{a, b} {
		f.run("git", "init", "-q", "-b", "main", repo)
	}
	hash := "-" + gitHash(a)[:10]
	if got, want := sessionLabel(a, "main", rexLabelSize), "app-main"+hash; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if sessionLabel(a, "main", rexLabelSize) == sessionLabel(b, "main", rexLabelSize) {
		t.Error("same label for two repositories")
	}
	long := sessionLabel(a, strings.Repeat("x", 200), rexLabelSize)
	if len(long) != 111 || !strings.HasSuffix(long, hash) {
		t.Errorf("long label %q", long)
	}
	// Zellij's 24 bytes leave 13 for the name: a fifth é would need bytes 13 and 14
	if got, want := sessionLabel(a, "ééééé", zellijLabelMax), "app-éééé"+hash; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Zellij

// zellijWorktree is the worktree of feature/x.y, and its Zellij session: repo-feature_x.y cut to 13 bytes.
func zellijWorktree(f *fixture) (string, string) {
	worktree := filepath.Join(f.repo, "feature/x.y")
	return worktree, "repo-feature_-" + gitHash(worktree)[:10]
}

func TestZellijInsideSwitchesSession(t *testing.T) {
	f := setup(t)
	setenv(t, inZellij)
	worktree, session := zellijWorktree(f)
	if err := f.switchIn("zellij", "feature/x.y"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.calls(), [][]string{
		{"zellij", "--version"},
		{"zellij", "action", "switch-session", session, "--cwd", worktree},
	})
}

func TestZellijOutsideAttachesInWorktree(t *testing.T) {
	f := setup(t)
	worktree, session := zellijWorktree(f)
	if err := f.switchIn("zellij", "feature/x.y"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.calls(), [][]string{{"zellij", "attach", "--create", session, "options", "--default-cwd", worktree}})
	if cwd, _ := os.ReadFile(filepath.Join(f.stubState, "zellij-cwd")); string(cwd) != worktree {
		t.Errorf("attached in %q", cwd)
	}
}

func TestZellijFailureKeepsWorktree(t *testing.T) {
	for _, c := range []struct {
		name   string
		env    map[string]string
		prints string
		want   string
	}{
		{"switching", inZellij, "Error: no such layout\n", "Error: no such layout"},
		{"switching without a message", inZellij, "", "exit status 1"},
		// Zellij has shown its own error by then, or nothing: wt still says where the worktree is
		{"attaching", nil, "", "exit status 1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := setup(t)
			setenv(t, c.env)
			worktree, _ := zellijWorktree(f)
			f.stub("zellij-error", c.prints)
			if f.switchIn("zellij", "feature/x.y") == nil {
				t.Fatal("succeeded")
			}
			want := "wt: worktree ready at " + worktree + "; Zellij session could not be opened: " + c.want
			if !strings.Contains(f.stderr.String(), want) {
				t.Errorf("stderr %q", f.stderr.String())
			}
			if !exists(worktree) {
				t.Error("worktree removed")
			}
		})
	}
}

// Zellij 0.44 is the first that can switch sessions from the command line.
func TestZellijVersionCheck(t *testing.T) {
	f := setup(t)
	setenv(t, inZellij)
	for _, c := range []struct {
		version string
		ok      bool
	}{
		{"zellij 0.43.1", false},
		{"zellij 0.44.0", true},
		{"zellij 0.45.1", true},
		{"zellij 0.100.0", true},
		{"zellij 1.0.0", true},
	} {
		t.Run(c.version, func(t *testing.T) {
			f.stub("zellij-version", c.version+"\n")
			if got := f.picked(rexWhoamiLive); (got == "zellij") != c.ok {
				t.Errorf("got %q", got)
			}
		})
	}
}

// zellijCalls are the calls to zellij but for those polling for a client, which vary in number.
func zellijCalls(f *fixture) [][]string {
	return slices.DeleteFunc(f.calls(), func(call []string) bool { return slices.Contains(call, "list-clients") })
}

// zellijCommand is a command to open: it holds what a shell would act on, or split at.
const zellijCommand = "echo \"$(touch pwned)\" 'a b'; \\; exit\n# end"

func TestZellijCommand(t *testing.T) {
	version := []string{"zellij", "--version"}
	list := []string{"zellij", "list-sessions", "--short", "--no-formatting"}
	tab := func(worktree, session string) []string {
		return []string{"zellij", "--session", session, "action", "new-tab", "--cwd", worktree, "--", "/bin/sh", "-c", zellijCommand}
	}
	switchTo := func(worktree, session string) []string {
		return []string{"zellij", "action", "switch-session", session, "--cwd", worktree}
	}
	attach := func(worktree, session string) []string {
		return []string{"zellij", "attach", "--create", session, "options", "--default-cwd", worktree}
	}
	for _, c := range []struct {
		name     string
		env      map[string]string
		version  string
		sessions string // what zellij lists, with the worktree's session when exists; nothing is no sessions at all
		exists   bool
		want     func(worktree, session string) [][]string
	}{
		// The session is shown, then a tab opens in it for the command
		{"inside, existing session", inZellij, "zellij 0.45.1", "other\n", true, func(w, s string) [][]string {
			return [][]string{version, version, list, switchTo(w, s), tab(w, s)}
		}},
		{"outside, existing session", nil, "zellij 0.45.1", "other\n", true, func(w, s string) [][]string {
			return [][]string{version, list, attach(w, s), tab(w, s)}
		}},
		// Before 0.45.1 a session can't start with a command: it has its shell tab, and then the command's
		{"inside, zellij 0.44.0", inZellij, "zellij 0.44.0", "other\n", false, func(w, s string) [][]string {
			return [][]string{version, version, switchTo(w, s), tab(w, s)}
		}},
		{"outside, zellij 0.44.0", nil, "zellij 0.44.0", "", false, func(w, s string) [][]string {
			return [][]string{version, attach(w, s), tab(w, s)}
		}},
		// The command runs in the first tab of a new session, which is not one that only starts with the label
		{"inside, new session", inZellij, "zellij 0.45.1", "other\n" + "label-and-more\n", false, func(w, s string) [][]string {
			return [][]string{version, version, list,
				{"zellij", "attach", "--create-background", s, "--", "/bin/sh", "-c", zellijCommand}, switchTo(w, s)}
		}},
		{"outside, new session", nil, "zellij 0.45.1", "other\n" + "label-and-more\n", false, func(w, s string) [][]string {
			return [][]string{version, list, {"zellij", "attach", "--create", s, "--", "/bin/sh", "-c", zellijCommand}}
		}},
		{"outside, no sessions at all", nil, "zellij 0.45.1", "", false, func(w, s string) [][]string {
			return [][]string{version, list, {"zellij", "attach", "--create", s, "--", "/bin/sh", "-c", zellijCommand}}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := setup(t)
			setenv(t, c.env)
			worktree, session := zellijWorktree(f)
			f.stub("zellij-version", c.version+"\n")
			if sessions := strings.ReplaceAll(c.sessions, "label", session); sessions != "" {
				if c.exists {
					sessions += session + "\n"
				}
				f.stub("zellij-sessions", sessions)
			}
			if err := f.launchIn("zellij", "feature/x.y", zellijCommand); err != nil {
				t.Fatal(err, f.stderr.String())
			}
			checkCalls(t, zellijCalls(f), c.want(worktree, session))
			// attaching in the worktree is what runs a command there, when the session is created with it
			if cwd, err := os.ReadFile(filepath.Join(f.stubState, "zellij-cwd")); err == nil && string(cwd) != worktree {
				t.Errorf("attached in %q", cwd)
			}
		})
	}
}

// Every failure is reported with the worktree, which stays, and none is retried or answered with another way
// to open the command: nothing runs after the call that failed.
func TestZellijCommandFailures(t *testing.T) {
	saved := zellijClientWait
	zellijClientWait /= 100 // a client that never connects: 100ms of waiting
	t.Cleanup(func() { zellijClientWait = saved })
	version := []string{"zellij", "--version"}
	list := []string{"zellij", "list-sessions", "--short", "--no-formatting"}
	create := func(flag, session string) []string {
		return []string{"zellij", "attach", flag, session, "--", "/bin/sh", "-c", zellijCommand}
	}
	switchTo := func(worktree, session string) []string {
		return []string{"zellij", "action", "switch-session", session, "--cwd", worktree}
	}
	attach := func(worktree, session string) []string {
		return []string{"zellij", "attach", "--create", session, "options", "--default-cwd", worktree}
	}
	tab := func(worktree, session string) []string {
		return []string{"zellij", "--session", session, "action", "new-tab", "--cwd", worktree, "--", "/bin/sh", "-c", zellijCommand}
	}
	for _, c := range []struct {
		name   string
		env    map[string]string
		exists bool
		stubs  map[string]string
		prints string // what wt reports of zellij's message
		want   func(worktree, session string) [][]string
	}{
		{"listing sessions", nil, false, map[string]string{"zellij-list-error": "boom\n"}, "boom",
			func(w, s string) [][]string { return [][]string{version, list} }},
		{"creating the session, outside", nil, false, map[string]string{"zellij-error": ""}, "exit status 1",
			func(w, s string) [][]string { return [][]string{version, list, create("--create", s)} }},
		{"creating the session, inside", inZellij, false, map[string]string{"zellij-error": "no room\n"}, "no room",
			func(w, s string) [][]string {
				return [][]string{version, version, list, create("--create-background", s)}
			}},
		{"switching to the session", inZellij, true, map[string]string{"zellij-error": "no switch\n"}, "no switch",
			func(w, s string) [][]string { return [][]string{version, version, list, switchTo(w, s)} }},
		{"attaching to the session", nil, true, map[string]string{"zellij-error": ""}, "exit status 1",
			func(w, s string) [][]string { return [][]string{version, list, attach(w, s)} }},
		{"attaching shows no client", nil, true, map[string]string{"zellij-no-client": ""}, "",
			func(w, s string) [][]string { return [][]string{version, list, attach(w, s)} }},
		{"switching shows no client", inZellij, true, map[string]string{"zellij-no-client": ""}, "",
			func(w, s string) [][]string { return [][]string{version, version, list, switchTo(w, s)} }},
		{"opening the tab, inside", inZellij, true, map[string]string{"zellij-tab-error": "no tab\n"}, "no tab",
			func(w, s string) [][]string {
				return [][]string{version, version, list, switchTo(w, s), tab(w, s)}
			}},
		{"opening the tab, outside", nil, true, map[string]string{"zellij-tab-error": "no tab\n"}, "no tab",
			func(w, s string) [][]string { return [][]string{version, list, attach(w, s), tab(w, s)} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := setup(t)
			setenv(t, c.env)
			worktree, session := zellijWorktree(f)
			if c.exists {
				f.stub("zellij-sessions", session+"\n")
			}
			for name, content := range c.stubs {
				f.stub(name, content)
			}
			if f.launchIn("zellij", "feature/x.y", zellijCommand) == nil {
				t.Fatal("succeeded")
			}
			msg := f.stderr.String()
			if want := "wt: worktree ready at " + worktree + "; Zellij session could not be opened: "; !strings.Contains(msg, want) || !strings.Contains(msg, c.prints) {
				t.Errorf("stderr %q", msg)
			}
			if !exists(worktree) {
				t.Error("worktree removed")
			}
			checkCalls(t, zellijCalls(f), c.want(worktree, session))
		})
	}
}

// Opening a tab with a command needs zellij 0.44 even outside Zellij, where attaching to a session doesn't.
func TestZellijCommandNeedsZellij044(t *testing.T) {
	f := setup(t)
	worktree, session := zellijWorktree(f)
	f.stub("zellij-version", "zellij 0.43.1\n")
	if f.launchIn("zellij", "feature/x.y", "claude") == nil {
		t.Fatal("succeeded")
	}
	if want := "wt: worktree ready at " + worktree + "; Zellij session could not be opened: "; !strings.Contains(f.stderr.String(), want) {
		t.Errorf("stderr %q", f.stderr.String())
	}
	checkCalls(t, zellijCalls(f), [][]string{{"zellij", "--version"}})
	f.clearCalls()
	if err := f.switchIn("zellij", "feature/x.y"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, zellijCalls(f), [][]string{{"zellij", "attach", "--create", session, "options", "--default-cwd", worktree}})
}

// zellijSocketMax is the longest socket path Zellij accepts: it turns down 104 bytes or more on macOS, and
// 108 or more elsewhere.
func zellijSocketMax() int {
	if runtime.GOOS == "darwin" {
		return 103
	}
	return 107
}

// socketDirLeaving is a $ZELLIJ_SOCKET_DIR that leaves budget bytes for the label in the socket path of a
// Zellij session, <dir>/contract_version_1/<label>.
func socketDirLeaving(budget int) string {
	return "/" + strings.Repeat("s", zellijSocketMax()-len("/contract_version_1/")-budget-1)
}

// zellijEnv sets the variables that decide where Zellij keeps its sockets; an empty one is unset.
func zellijEnv(t *testing.T, socketDir, runtimeDir, tempDir string) {
	for name, value := range map[string]string{"ZELLIJ_SOCKET_DIR": socketDir, "XDG_RUNTIME_DIR": runtimeDir, "TMPDIR": tempDir} {
		t.Setenv(name, value)
		if value == "" {
			os.Unsetenv(name)
		}
	}
}

// A label gets what its session's socket folder leaves of the longest socket path, 24 bytes at most. The
// folder is found as Zellij finds it: with macOS's usual $TMPDIR and a 3-digit uid, the default takes 79 of
// the 103 bytes, leaving exactly 24.
func TestZellijLabelSize(t *testing.T) {
	uid := strconv.Itoa(os.Getuid())
	socket := socketDirLeaving(17)
	temp := "/" + strings.Repeat("t", 59) // 60 bytes, which leave less than 24 for a label
	tempFolder := temp + "/zellij-" + uid + "/contract_version_1/"
	runtimeFolder := "/run/user/1/zellij/contract_version_1/"
	if runtime.GOOS == "darwin" {
		runtimeFolder = tempFolder // macOS has no runtime folder
	}
	usual := "/var/folders/6j/6zx000hd2mz2vxf22zvty6340000gp/T/" // macOS's usual $TMPDIR: 49 bytes with its last slash
	for _, c := range []struct {
		name       string
		socketDir  string
		runtimeDir string
		tempDir    string
		folder     string
	}{
		{"$ZELLIJ_SOCKET_DIR", socket, "/run/user/1", temp, socket + "/contract_version_1/"},
		{"$ZELLIJ_SOCKET_DIR with a slash", socket + "/", "/run/user/1", temp, socket + "/contract_version_1/"},
		{"runtime folder", "", "/run/user/1", temp, runtimeFolder},
		{"relative runtime folder", "", "run/user/1", temp, tempFolder},
		{"temp folder", "", "", temp, tempFolder},
		{"temp folder with a slash", "", "", temp + "/", tempFolder},
		{"usual temp folder", "", "", usual, usual + "zellij-" + uid + "/contract_version_1/"},
	} {
		t.Run(c.name, func(t *testing.T) {
			zellijEnv(t, c.socketDir, c.runtimeDir, c.tempDir)
			if got, want := zellijLabelSize(), min(24, zellijSocketMax()-len(c.folder)); got != want {
				t.Errorf("got %d, want %d", got, want)
			}
		})
	}
}

// Zellij takes an empty $ZELLIJ_SOCKET_DIR as set: its sockets go in a folder of the current directory.
func TestZellijEmptySocketDir(t *testing.T) {
	t.Setenv("ZELLIJ_SOCKET_DIR", "")
	if got := zellijSocketDir(); got != "contract_version_1" {
		t.Errorf("got %q", got)
	}
}

// A label is cut to what its socket folder leaves for it (see socketDirLeaving), at most 24 bytes, without
// splitting a character, and keeps its hash.
func TestZellijLabelsFitTheSocketPath(t *testing.T) {
	for _, c := range []struct {
		name      string
		socketDir string
		branch    string
		kept      string // the part of the repository and branch that fits before the hash
	}{
		{"cut to the budget", socketDirLeaving(17), "feature/x.y", "repo-f"},
		{"smallest budget", socketDirLeaving(15), "feature/x.y", "repo"},
		{"cut between characters", socketDirLeaving(17), "ééééé", "repo-"},
		{"cut after a character", socketDirLeaving(18), "ééééé", "repo-é"},
		{"capped at 24", socketDirLeaving(30), "feature/x.y", "repo-feature_"},
		{"default socket folder", "", "feature/x.y", "repo-feature_"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := setup(t)
			zellijEnv(t, c.socketDir, "", "/tmp")
			if err := f.switchIn("zellij", c.branch); err != nil {
				t.Fatal(err, f.stderr.String())
			}
			worktree := filepath.Join(f.repo, c.branch)
			label := c.kept + "-" + gitHash(worktree)[:10]
			checkCalls(t, f.calls(), [][]string{{"zellij", "attach", "--create", label, "options", "--default-cwd", worktree}})
		})
	}
}

// WT_OPEN_COMMAND

func TestCommandRunsInWorktreeWithItsDetails(t *testing.T) {
	f := setup(t)
	out := filepath.Join(f.root, "out")
	setenv(t, map[string]string{"OUT": out,
		"WT_OPEN_COMMAND": `printf '%s\n' "$WT_WORKTREE" "$WT_BRANCH" "$WT_SESSION" "$(pwd -P)" > "$OUT"`})
	branch := "x$(touch${IFS}pwned)"
	if err := f.switchIn("command", branch); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	worktree := filepath.Join(f.repo, branch)
	got, _ := os.ReadFile(out)
	if want := strings.Join([]string{worktree, branch, sessionLabel(worktree, branch, rexLabelSize), worktree, ""}, "\n"); string(got) != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if exists(filepath.Join(worktree, "pwned")) {
		t.Error("the branch name ran as a command")
	}
}

func TestCommandFailureKeepsWorktree(t *testing.T) {
	f := setup(t)
	t.Setenv("WT_OPEN_COMMAND", "exit 3")
	if f.switchIn("command", "feature/x.y") == nil {
		t.Fatal("succeeded")
	}
	worktree := filepath.Join(f.repo, "feature/x.y")
	if want := "wt: worktree ready at " + worktree + "; WT_OPEN_COMMAND failed: exit status 3"; !strings.Contains(f.stderr.String(), want) {
		t.Errorf("stderr %q", f.stderr.String())
	}
	if !exists(worktree) {
		t.Error("worktree removed")
	}
}

func TestCommandReceivesTheCommandAsData(t *testing.T) {
	for _, c := range []struct {
		name, inherited, command, want string
	}{
		{"a shell", "", "", "set|"},
		{"a shell, not an inherited command", "stale", "", "set|"},
		{"a command, not an inherited one", "stale", "claude --resume", "set|claude --resume"},
		{"a command nothing acts on", "", "echo $(touch pwned)\n'x'", "set|echo $(touch pwned)\n'x'"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := setup(t)
			out := filepath.Join(f.root, "out")
			setenv(t, map[string]string{"OUT": out,
				"WT_OPEN_COMMAND": `printf '%s|%s' "${WT_COMMAND+set}" "$WT_COMMAND" > "$OUT"`})
			if c.inherited != "" {
				t.Setenv("WT_COMMAND", c.inherited)
			}
			if err := f.launchIn("command", "feature/x.y", c.command); err != nil {
				t.Fatal(err, f.stderr.String())
			}
			if got, _ := os.ReadFile(out); string(got) != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
			if exists(filepath.Join(f.repo, "feature/x.y", "pwned")) {
				t.Error("the command ran as part of WT_OPEN_COMMAND")
			}
		})
	}
}

// Commands

// writeConfig writes dir/wt/config.json, returning its path.
func writeConfig(t *testing.T, dir, data string) string {
	t.Helper()
	file := filepath.Join(dir, "wt", "config.json")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

// config writes the user's command configuration, where setup points $XDG_CONFIG_HOME.
func (f *fixture) config(data string) string {
	return writeConfig(f.t, filepath.Join(f.root, "config"), data)
}

// launches are the rex calls that open a session or a window.
func (f *fixture) launches() [][]string {
	var calls [][]string
	for _, call := range f.rexCalls() {
		if call[0] == "new" || call[0] == "window" {
			calls = append(calls, call)
		}
	}
	return calls
}

func TestCommandConfig(t *testing.T) {
	f := setup(t)
	home := filepath.Join(f.root, "home")
	t.Setenv("HOME", home)
	load := func() commandConfig {
		t.Helper()
		cfg, err := loadCommandConfig()
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	same := func(a, b commandConfig) bool {
		return a.DefaultCommand == b.DefaultCommand && maps.Equal(a.Keymaps, b.Keymaps)
	}

	// No file, or nothing configured, opens a shell as before.
	for _, data := range []string{"", "{}", `{"default_command": " \n\t", "keymaps": {}}`, `{"default_command": null, "keymaps": null}`} {
		if data != "" {
			f.config(data)
		}
		if cfg := load(); !same(cfg, commandConfig{}) {
			t.Errorf("%q: %+v", data, cfg)
		}
	}

	// An absolute $XDG_CONFIG_HOME wins; otherwise the configuration is in ~/.config.
	writeConfig(t, filepath.Join(home, ".config"), `{"default_command": "home"}`)
	f.config(`{"default_command": "xdg"}`)
	if got := load().DefaultCommand; got != "xdg" {
		t.Errorf("absolute XDG_CONFIG_HOME: %q", got)
	}
	t.Setenv("XDG_CONFIG_HOME", "relative")
	if got := load().DefaultCommand; got != "home" {
		t.Errorf("relative XDG_CONFIG_HOME: %q", got)
	}
	os.Unsetenv("XDG_CONFIG_HOME")
	if got := load().DefaultCommand; got != "home" {
		t.Errorf("no XDG_CONFIG_HOME: %q", got)
	}
	os.Unsetenv("HOME")
	if _, err := loadCommandConfig(); err == nil || !strings.HasPrefix(err.Error(), "cannot locate wt config: ") {
		t.Errorf("no HOME: %v", err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(f.root, "config"))

	// Commands are shell snippets, kept exactly as written.
	snippets := commandConfig{DefaultCommand: " printf 'DEFAULT:%s\\n' \"$PWD\"\n\texec claude ",
		Keymaps: map[string]string{"ctrl-o": "opencode --model 'a b' # <&>", "alt-,": "x; y", "CTRL-A": "`z`"}}
	data, _ := json.Marshal(snippets)
	f.config(string(data))
	if cfg := load(); !same(cfg, snippets) {
		t.Errorf("got %+v\nwant %+v", cfg, snippets)
	}

	for _, c := range []struct{ data, detail string }{
		{"", "expected one JSON object"},
		{" \n", "expected one JSON object"},
		{"null", "expected one JSON object"},
		{`["claude"]`, "expected one JSON object"},
		{`"claude"`, "expected one JSON object"},
		{`{} {}`, "expected one JSON object"},
		{`{"default_command": "claude"} x`, "expected one JSON object"},
		{`{"default_command": "claude"`, "unexpected EOF"},
		{`{"default_command": "claude",}`, "invalid character"},
		{`{"default-command": "claude"}`, `unknown field "default-command"`},
		{`{"default_command": ["claude"]}`, "cannot unmarshal"},
		{`{"keymaps": ["ctrl-o"]}`, "cannot unmarshal"},
		{`{"keymaps": {"ctrl-o": 1}}`, "cannot unmarshal"},
		{`{"default_command": "claude\u0000"}`, "default_command must not contain NUL"},
		{`{"keymaps": {"ctrl-o": " \n"}}`, `keymaps["ctrl-o"] must be a non-empty command without NUL`},
		{`{"keymaps": {"ctrl-o": null}}`, `keymaps["ctrl-o"] must be a non-empty command without NUL`},
		{`{"keymaps": {"ctrl-o": "a\u0000b"}}`, `keymaps["ctrl-o"] must be a non-empty command without NUL`},
		{`{"keymaps": {"ctrl-o,ctrl-p": "x"}}`, `invalid keymap key "ctrl-o,ctrl-p"`},
		{`{"keymaps": {"ctrl-o,": "x"}}`, `invalid keymap key "ctrl-o,"`},
		{`{"keymaps": {"": "x"}}`, `invalid keymap key ""`},
		{`{"keymaps": {"ctrl-bogus": "x"}}`, `invalid keymap key "ctrl-bogus"`},
		{`{"keymaps": {"load": "x"}}`, `invalid keymap key "load"`},
		{`{"keymaps": {"every(1)": "x"}}`, `invalid keymap key "every(1)"`},
		{`{"keymaps": {"left-click": "x"}}`, `invalid keymap key "left-click"`},
		{`{"keymaps": {"\u0001": "x"}}`, `invalid keymap key "\x01"`},
		{`{"keymaps": {"enter": "x"}}`, `keymap key "enter" is reserved`},
		{`{"keymaps": {"return": "x"}}`, `keymap key "return" is reserved`},
		{`{"keymaps": {"ctrl-m": "x"}}`, `keymap key "ctrl-m" is reserved`},
		{`{"keymaps": {"esc": "x"}}`, `keymap key "esc" is reserved`},
		{`{"keymaps": {"ctrl-c": "x"}}`, `keymap key "ctrl-c" is reserved`},
		{`{"keymaps": {"ctrl-g": "x"}}`, `keymap key "ctrl-g" is reserved`},
		{`{"keymaps": {"ctrl-x": "x"}}`, `keymap key "ctrl-x" is reserved`},
		{`{"keymaps": {"CTRL-T": "x"}}`, `keymap key "CTRL-T" is reserved`},
		{`{"keymaps": {"ctrl-a": "x", "CTRL-A": "y"}}`, `keymap keys "CTRL-A" and "ctrl-a" name the same key`},
		{`{"keymaps": {"bs": "x", "backspace": "y"}}`, `keymap keys "backspace" and "bs" name the same key`},
	} {
		file := f.config(c.data)
		cfg, err := loadCommandConfig()
		if err == nil || !strings.HasPrefix(err.Error(), "config "+file+": ") || !strings.Contains(err.Error(), c.detail) {
			t.Errorf("%q: %+v, %v", c.data, cfg, err)
		}
	}

	// A broken configuration stops the commands opening worktrees before any picker, change, multiplexer or
	// GitHub refresh. No cache is written, so a refresh would be tried, and fail (the remote isn't GitHub's),
	// with another error than the configuration's.
	file := f.config(`{"keymaps": {"ctrl-x": "claude"}}`)
	t.Setenv("WT_MULTIPLEXER", "rex")
	t.Setenv("GH_REPO", "")
	cloned := filepath.Join(f.root, "cloned")
	refs, trees := f.git("for-each-ref"), f.git("worktree", "list", "--porcelain")
	f.picks([]string{"new-topic", "enter"}, fzf.ExitNoMatch)
	for _, args := range [][]string{nil, {"issue"}, {"pr"}, {"clone", f.remote, cloned}} {
		f.stderr.Reset()
		if run(args) == 0 || !strings.Contains(f.stderr.String(), "wt: config "+file+`: keymap key "ctrl-x" is reserved`) {
			t.Errorf("%q: %q", args, f.stderr.String())
		}
	}
	if f.pickerShown || exists(cloned) || mux != nil {
		t.Errorf("picker shown %t, cloned %t, multiplexer %v", f.pickerShown, exists(cloned), mux)
	}
	if f.git("for-each-ref") != refs || f.git("worktree", "list", "--porcelain") != trees {
		t.Errorf("branches or worktrees changed:\n%s\n%s", f.git("for-each-ref"), f.git("worktree", "list", "--porcelain"))
	}
	// Opening the pickers (and the files behind them) or refreshing the lists would have left these.
	if dir, ok := os.LookupEnv("WT_REFRESHED"); ok || exists(filepath.Join(f.repo, ".git", "wt-state")) {
		t.Errorf("a picker was set up: WT_REFRESHED %q, state folder %t", dir, exists(filepath.Join(f.repo, ".git", "wt-state")))
	}
	checkCalls(t, f.calls(), nil)
	// Commands that don't open worktrees don't read it.
	for _, args := range [][]string{{"--help"}, {"list"}, {"--list-branches"}, {"--header"}, {"--lines", "issue"}, {"--toggle"}} {
		if _, stderr, ok := f.wt(args...); !ok {
			t.Errorf("%q failed: %s", args, stderr)
		}
	}
}

func TestCommandSelection(t *testing.T) {
	setup(t)
	// Expected keys and multi-selection set by the user would change what fzf prints.
	t.Setenv("FZF_DEFAULT_OPTS", "--expect=ctrl-y --multi")
	t.Setenv("FZF_DEFAULT_OPTS_FILE", "")
	cfg := commandConfig{DefaultCommand: "default", Keymaps: map[string]string{"ctrl-o": "opencode"}}
	row := "topic [wt]\tmeta\trefs/heads/topic"
	for _, c := range []struct {
		name                 string
		out                  []string
		code                 int
		allowQuery           bool
		picked, command, err string
	}{
		{"enter keeps the command", []string{"query", "enter", row}, fzf.ExitOk, true, row, "claude", ""},
		{"a mouse accept keeps it", []string{"query", "", row}, fzf.ExitOk, false, row, "claude", ""},
		{"a key picks its command", []string{"query", "ctrl-o", row}, fzf.ExitOk, false, row, "opencode", ""},
		{"new branch typed", []string{"new-topic", "ctrl-o"}, fzf.ExitNoMatch, true, "new-topic", "opencode", ""},
		{"query matching no issue", []string{"new-topic", "ctrl-o"}, fzf.ExitNoMatch, false, "", "", ""},
		// Print actions in FZF_DEFAULT_OPTS, like --bind=start:print(main), print between the key and the row.
		{"print before the row", []string{"query", "enter", "main", row}, fzf.ExitOk, false, row, "claude", ""},
		{"print before the row of a key", []string{"query", "ctrl-o", "main", "other", row}, fzf.ExitOk, false, row, "opencode", ""},
		{"print before the row of a mouse accept", []string{"query", "", "ctrl-y", row}, fzf.ExitOk, true, row, "claude", ""},
		{"print with new branch typed", []string{"new-topic", "enter", "main"}, fzf.ExitNoMatch, true, "new-topic", "claude", ""},
		{"print with query matching no issue", []string{"new-topic", "ctrl-o", "main"}, fzf.ExitNoMatch, false, "", "", ""},
		{"empty query", []string{"", "enter"}, fzf.ExitNoMatch, true, "", "", ""},
		{"cancelled", []string{"query", "ctrl-o", row}, fzf.ExitInterrupt, true, "", "", ""},
		{"cancelled without output", nil, fzf.ExitInterrupt, true, "", "", ""},
		{"no output", nil, fzf.ExitOk, true, "", "", ""},
		{"unknown key", []string{"query", "ctrl-y", row}, fzf.ExitOk, true, "", "", `unexpected picker key "ctrl-y"`},
		{"no key", []string{"query"}, fzf.ExitOk, true, "", "", "invalid launch picker output"},
		{"fzf failed", []string{"query", "enter", row}, fzf.ExitError, true, "", "", errReported.Error()},
	} {
		t.Run(c.name, func(t *testing.T) {
			pick = func(_ []string, args ...string) ([]string, int) {
				opts, err := fzf.ParseOptions(true, args)
				if err != nil {
					t.Fatal(err)
				}
				if keys := slices.Sorted(maps.Values(opts.Expect)); !slices.Equal(keys, []string{"ctrl-o", "enter"}) || opts.Multi != 0 {
					t.Errorf("expects %q, multi %d", keys, opts.Multi)
				}
				return c.out, c.code
			}
			picked, command, err := pickLaunch([]string{row}, cfg, "claude", c.allowQuery)
			if picked != c.picked || command != c.command || fmt.Sprint(err) != cmp.Or(c.err, "<nil>") {
				t.Errorf("got %q, %q, %v", picked, command, err)
			}
		})
	}
}

// A picker is always shown: --exit-0 in FZF_DEFAULT_OPTS would skip one with nothing to match, like the one
// naming a new branch, and --filter would print matches without showing any. What fzf runs with is checked
// rather than run, as an interactive fzf needs a terminal.
func TestPickersShownDespiteDefaultOptions(t *testing.T) {
	setup(t)
	t.Setenv("FZF_DEFAULT_OPTS", "--exit-0 --filter=topic")
	t.Setenv("FZF_DEFAULT_OPTS_FILE", "")
	var opts *fzf.Options
	pick = func(_ []string, args ...string) ([]string, int) {
		var err error
		if opts, err = fzfOptions(args); err != nil {
			t.Fatal(err)
		}
		return nil, fzf.ExitInterrupt
	}
	if _, _, err := pickLaunch(nil, commandConfig{}, "claude", true, "--prompt=New branch> ", "--query=5-issue"); err != nil {
		t.Fatal(err)
	}
	if opts == nil {
		t.Fatal("no picker shown")
	}
	if opts.Exit0 || opts.Filter != nil {
		t.Errorf("exit-0 %t, filter mode %t", opts.Exit0, opts.Filter != nil)
	}
}

// Both GitHub pickers must override user defaults that wrap or keep the right end, as those modes undo
// the title-prefix/right-marker layout.
func TestGitHubPickerKeepsFrozenRightWithoutClippingTitleStart(t *testing.T) {
	setup(t)
	t.Setenv("FZF_DEFAULT_OPTS", "--wrap --keep-right")
	t.Setenv("FZF_DEFAULT_OPTS_FILE", "")
	if err := writeCache("issues", []string{"1\t2026-01-01\tIssue title\t"}); err != nil {
		t.Fatal(err)
	}
	if err := writeCache("prs", []string{"2\t2026-01-01\tfalse\tfalse\tbranch\tPR title\tme\t\tnone\tfalse"}); err != nil {
		t.Fatal(err)
	}
	shown := 0
	pick = func(input []string, args ...string) ([]string, int) {
		shown++
		if len(input) != 1 {
			t.Errorf("picker input: %q", input)
		}
		opts, err := fzfOptions(args)
		if err != nil {
			t.Fatal(err)
		}
		if opts.FreezeRight != 1 || opts.Wrap || opts.KeepRight || opts.WithNthExpr != "4.." {
			t.Errorf("picker layout: freeze-right=%d, wrap=%t, keep-right=%t, with-nth=%q",
				opts.FreezeRight, opts.Wrap, opts.KeepRight, opts.WithNthExpr)
		}
		return nil, fzf.ExitInterrupt
	}
	for _, kind := range []string{"issue", "pr"} {
		if err := cmdGitHub(kind); err != nil {
			t.Fatal(err)
		}
	}
	if shown != 2 {
		t.Errorf("shown %d pickers, want 2", shown)
	}
}

// runPicking runs a command whose pickers give answers, checking every answer was used.
func (f *fixture) runPicking(run func() error, answers ...pickAnswer) error {
	f.t.Helper()
	mux = nil
	f.stderr.Reset()
	f.clearCalls()
	f.answer(answers...)
	err := run()
	if len(f.answers) > 0 {
		f.t.Errorf("pickers not shown for %v", f.answers)
	}
	return err
}

func TestCommandNewBranchTyped(t *testing.T) {
	f := setup(t)
	f.config(`{"default_command": "claude", "keymaps": {"ctrl-o": "opencode"}}`)
	// A branch typed in the branch picker, matching none, is created and opened with the key's command.
	if err := f.runPicking(cmdSwitch, pickAnswer{[]string{"new-topic", "ctrl-o"}, fzf.ExitNoMatch}); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	if !f.hasRef("refs/heads/new-topic") {
		t.Error("branch not created")
	}
	checkCalls(t, f.calls(), [][]string{
		{"tmux", "has-session", "-t", "=new-topic"},
		{"tmux", "new-session", "-s", "new-topic", "-c", filepath.Join(f.repo, "new-topic"), "/bin/sh", "-c", "opencode"},
	})
}

func TestCommandIssueSelection(t *testing.T) {
	f := setup(t)
	t.Setenv("WT_MULTIPLEXER", "rex")
	f.config(`{"default_command": "claude", "keymaps": {"ctrl-o": "opencode", "alt-c": "codex"}}`)
	if err := writeCache("issues", []string{"5\t2026-01-01T00:00:00Z\tAn issue\t"}); err != nil {
		t.Fatal(err)
	}
	f.git("branch", "5-existing")
	worktree := filepath.Join(f.repo, "5-existing")
	label := "repo-5-existing-" + gitHash(worktree)[:10]
	issue := issueLines()[0]
	branch := func() string {
		for _, line := range listBranches() {
			if strings.HasPrefix(line, "5-existing") {
				return line
			}
		}
		t.Fatal("5-existing not listed")
		return ""
	}
	open := func(answers ...pickAnswer) [][]string {
		t.Helper()
		if err := f.runPicking(func() error { return cmdGitHub("issue") }, answers...); err != nil {
			t.Fatal(err, f.stderr.String())
		}
		return f.launches()
	}
	window := func(command string) [][]string {
		return [][]string{{"window", "new", "-s", session(0), "-c", worktree, "--json", "--", "/bin/sh", "-c", command}}
	}

	// The branch picker opens the issue's branch with the default command, in a new session.
	if err := f.runPicking(cmdSwitch, pickAnswer{[]string{"", "enter", branch()}, fzf.ExitOk}); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.launches(), [][]string{{"new", label, "-c", worktree, "--json", "--", "/bin/sh", "-c", "claude"}})
	// Picking the issue, then its branch, adds a window to that session, with the command the issue was
	// picked with unless the branch is picked with another.
	checkCalls(t, open(pickAnswer{[]string{"", "ctrl-o", issue}, fzf.ExitOk}, pickAnswer{[]string{"", "enter", branch()}, fzf.ExitOk}),
		window("opencode"))
	checkCalls(t, open(pickAnswer{[]string{"", "enter", issue}, fzf.ExitOk}, pickAnswer{[]string{"", "", branch()}, fzf.ExitOk}),
		window("claude"))
	checkCalls(t, open(pickAnswer{[]string{"", "ctrl-o", issue}, fzf.ExitOk}, pickAnswer{[]string{"", "alt-c", branch()}, fzf.ExitOk}),
		window("codex"))
	want := []rexWindow{{session(0), windowID(0)}, {session(0), windowID(1)}, {session(0), windowID(2)}, {session(0), windowID(3)}}
	if !slices.Equal(f.windows(), want) || !slices.Equal(f.sessionIDs(), []string{session(0)}) {
		t.Errorf("sessions %q, windows %q", f.sessionIDs(), f.windows())
	}

	// Cancelling any of the pickers changes nothing.
	refs := f.git("for-each-ref")
	cancel := pickAnswer{[]string{"5-other", "ctrl-o"}, fzf.ExitInterrupt}
	for name, answers := range map[string][]pickAnswer{
		"issue picker":  {cancel},
		"branch picker": {{[]string{"", "ctrl-o", issue}, fzf.ExitOk}, cancel},
		"name prompt":   {{[]string{"", "ctrl-o", issue}, fzf.ExitOk}, {[]string{"", "enter", "+ new branch"}, fzf.ExitOk}, cancel},
	} {
		if launches := open(answers...); launches != nil {
			t.Errorf("%s: launched %q", name, launches)
		}
	}
	if f.git("for-each-ref") != refs || !slices.Equal(f.windows(), want) || !slices.Equal(f.sessionIDs(), []string{session(0)}) {
		t.Errorf("changed: sessions %q, windows %q", f.sessionIDs(), f.windows())
	}

	// A new branch, named in a prompt that inherits the issue's command and can pick another.
	fix := filepath.Join(f.repo, "5-my-fix")
	checkCalls(t, open(pickAnswer{[]string{"", "enter", issue}, fzf.ExitOk}, pickAnswer{[]string{"", "enter", "+ new branch"}, fzf.ExitOk},
		pickAnswer{[]string{"my-fix", "ctrl-o"}, fzf.ExitNoMatch}),
		[][]string{{"new", "repo-5-my-fix-" + gitHash(fix)[:10], "-c", fix, "--json", "--", "/bin/sh", "-c", "opencode"}})
	if !f.hasRef("refs/heads/5-my-fix") {
		t.Error("branch 5-my-fix not created")
	}
}

// The prompts after picking an issue offer the command it was picked with, not the configured default,
// and Enter in them keeps it.
func TestCommandIssuePromptsInheritTheCommand(t *testing.T) {
	f := setup(t)
	f.config(`{"default_command": "claude", "keymaps": {"ctrl-o": "opencode"}}`)
	if err := writeCache("issues", []string{"5\t2026-01-01T00:00:00Z\tAn issue\t"}); err != nil {
		t.Fatal(err)
	}
	f.git("branch", "5-existing")
	issue := issueLines()[0]
	var enter []string // what Enter does in each picker shown after the first, as the footers say
	f.answer(pickAnswer{[]string{"", "ctrl-o", issue}, fzf.ExitOk},
		pickAnswer{[]string{"", "enter", "+ new branch"}, fzf.ExitOk}, pickAnswer{[]string{"my-fix", "enter"}, fzf.ExitNoMatch})
	answer := pick
	pick = func(input []string, args ...string) ([]string, int) {
		if f.pickerShown { // not the first
			opts, err := fzfOptions(args)
			if err != nil {
				t.Fatal(err)
			}
			enter = append(enter, strings.Join(opts.Footer, "\n"))
		}
		return answer(input, args...)
	}
	mux = nil
	if err := cmdGitHub("issue"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	if len(enter) != 2 {
		t.Fatalf("%d nested pickers shown", len(enter))
	}
	for i, footer := range enter {
		if !strings.HasPrefix(footer, "Enter: "+strconv.Quote("opencode")) || strings.Contains(footer, strconv.Quote("claude")) {
			t.Errorf("picker %d's footer %q", i+1, footer)
		}
	}
	fix := filepath.Join(f.repo, "5-my-fix")
	checkCalls(t, f.calls(), [][]string{{"tmux", "has-session", "-t", "=5-my-fix"},
		{"tmux", "new-session", "-s", "5-my-fix", "-c", fix, "/bin/sh", "-c", "opencode"}})
}

func TestCommandPRSelection(t *testing.T) {
	f := setup(t)
	t.Setenv("WT_MULTIPLEXER", "rex")
	f.config(`{"default_command": "claude", "keymaps": {"ctrl-o": "opencode"}}`)
	f.remoteBranch("pr-branch")
	f.git("update-ref", "-d", "refs/remotes/origin/pr-branch")
	if err := writeCache("prs", []string{"7\t2026-01-01T00:00:00Z\tfalse\tfalse\tpr-branch\tTitle\tme\t",
		"8\t2026-01-01T00:00:00Z\tfalse\tfalse\tgone-branch\tGone\tme\t"}); err != nil {
		t.Fatal(err)
	}
	rows := map[string]string{}
	for _, line := range prLines() {
		rows[strings.Split(line, "\t")[1]] = line
	}
	open := func(n, key string) error {
		return f.runPicking(func() error { return cmdGitHub("pr") }, pickAnswer{[]string{"", key, rows[n]}, fzf.ExitOk})
	}
	worktree := filepath.Join(f.repo, "pr-branch")

	// The PR's branch is fetched and opened with the command picked, then each pick adds a window to its session.
	if err := open("7", "ctrl-o"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.launches(), [][]string{{"new", "repo-pr-branch-" + gitHash(worktree)[:10], "-c", worktree, "--json", "--", "/bin/sh", "-c", "opencode"}})
	for _, key := range []string{"enter", "ctrl-o"} {
		if err := open("7", key); err != nil {
			t.Fatal(err, f.stderr.String())
		}
	}
	want := []rexWindow{{session(0), windowID(0)}, {session(0), windowID(1)}, {session(0), windowID(2)}}
	if !slices.Equal(f.windows(), want) || !slices.Equal(f.sessionIDs(), []string{session(0)}) {
		t.Errorf("sessions %q, windows %q", f.sessionIDs(), f.windows())
	}

	// A PR whose branch can't be fetched opens nothing.
	if open("8", "ctrl-o") == nil || !strings.Contains(f.stderr.String(), "failed to fetch PR #8") {
		t.Errorf("stderr %q", f.stderr.String())
	}
	checkCalls(t, f.launches(), nil)
	if !slices.Equal(f.windows(), want) {
		t.Errorf("windows %q", f.windows())
	}
}

// A PR from a fork is fetched from refs/pull/<n>/head, and its branch opened, with the command, in the
// session it already has; a failed fetch opens nothing.
func TestCommandCrossRepoPR(t *testing.T) {
	f := setup(t)
	f.config(`{"default_command": "claude", "keymaps": {"ctrl-o": "opencode"}}`)
	f.git("update-ref", "refs/pull/9/head", "HEAD")
	f.git("push", "-q", "origin", "refs/pull/9/head")
	f.git("update-ref", "-d", "refs/pull/9/head")
	if err := writeCache("prs", []string{"9\t2026-01-01T00:00:00Z\tfalse\ttrue\tfork-branch\tFork\tthem\t",
		"10\t2026-01-01T00:00:00Z\tfalse\ttrue\tlost-branch\tLost\tthem\t"}); err != nil {
		t.Fatal(err)
	}
	rows := map[string]string{}
	for _, line := range prLines() {
		rows[strings.Split(line, "\t")[1]] = line
	}
	open := func(n, key string) error {
		return f.runPicking(func() error { return cmdGitHub("pr") }, pickAnswer{[]string{"", key, rows[n]}, fzf.ExitOk})
	}
	worktree := filepath.Join(f.repo, "fork-branch")
	probe := []string{"tmux", "has-session", "-t", "=fork-branch"}

	if err := open("9", "ctrl-o"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	if !f.hasRef("refs/heads/fork-branch") {
		t.Error("branch not fetched")
	}
	checkCalls(t, f.calls(), [][]string{probe, {"tmux", "new-session", "-s", "fork-branch", "-c", worktree, "/bin/sh", "-c", "opencode"}})
	f.stub("tmux-has-session", "")
	if err := open("9", "enter"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.calls(), [][]string{probe, {"tmux", "new-window", "-t", "=fork-branch:", "-c", worktree, "/bin/sh", "-c", "claude"},
		{"tmux", "attach-session", "-t", "=fork-branch"}})

	if open("10", "ctrl-o") == nil || !strings.Contains(f.stderr.String(), "failed to fetch PR #10") {
		t.Errorf("stderr %q", f.stderr.String())
	}
	checkCalls(t, f.calls(), nil)
	if f.hasRef("refs/heads/lost-branch") || exists(filepath.Join(f.repo, "lost-branch")) {
		t.Error("branch or worktree created")
	}
}

func TestCommandSessions(t *testing.T) {
	for _, first := range []string{"", "claude"} {
		opened := "first opened with " + cmp.Or(first, "a shell")
		for _, inside := range []bool{false, true} {
			t.Run(fmt.Sprintf("tmux, inside tmux %t, %s", inside, opened), func(t *testing.T) {
				f := setup(t)
				if inside {
					setenv(t, inTmux)
				}
				f.git("branch", "feature/x.y")
				worktree := filepath.Join(f.repo, "feature/x.y")
				probe := []string{"tmux", "has-session", "-t", "=feature_x_y"}
				show := []string{"tmux", "attach-session", "-t", "=feature_x_y"}
				if inside {
					show = []string{"tmux", "switch-client", "-t", "=feature_x_y"}
				}
				open := func(command string, want ...[]string) {
					t.Helper()
					mux = nil
					f.clearCalls()
					if err := switchToBranch("feature/x.y", command); err != nil {
						t.Fatal(err, f.stderr.String())
					}
					checkCalls(t, f.calls(), want)
				}

				// No session yet: one is created, its first window running the command.
				run := []string{"-c", worktree}
				if first != "" {
					run = append(run, "/bin/sh", "-c", first)
				}
				switch {
				case first == "" && !inside:
					open(first, append([]string{"tmux", "new-session", "-A", "-s", "feature_x_y"}, run...))
				case !inside:
					// attached as it's created
					open(first, probe, append([]string{"tmux", "new-session", "-s", "feature_x_y"}, run...))
				default:
					open(first, probe, append([]string{"tmux", "new-session", "-d", "-s", "feature_x_y"}, run...), show)
				}
				// The session exists: each command gets a new window in it, at the worktree, and is shown.
				f.stub("tmux-has-session", "")
				for _, command := range []string{"claude", "opencode --model 'a b'"} {
					open(command, probe, []string{"tmux", "new-window", "-t", "=feature_x_y:", "-c", worktree, "/bin/sh", "-c", command}, show)
				}
				// A shell just shows the session.
				if inside {
					open("", probe, show)
				} else {
					open("", []string{"tmux", "new-session", "-A", "-s", "feature_x_y", "-c", worktree})
				}
			})
		}

		t.Run("rex, "+opened, func(t *testing.T) {
			f, worktree, label := rexFixture(t)
			create := []string{"new", label, "-c", worktree, "--json"}
			if first != "" {
				create = append(create, "--", "/bin/sh", "-c", first)
			}
			if err := f.launchIn("rex", "feature/x.y", first); err != nil {
				t.Fatal(err, f.stderr.String())
			}
			// The session is created with the one window, running the command if any.
			checkCalls(t, f.rexCalls(), [][]string{{"ls", "--json"}, create, {"do", "session.select", "session_id=" + session(0)}})
			want := []rexWindow{{session(0), windowID(0)}}
			if !slices.Equal(f.windows(), want) {
				t.Errorf("windows %q", f.windows())
			}
			// Each command opens, and shows, a new window of that session at the worktree, also through a symlink.
			alias := filepath.Join(f.root, "alias")
			if err := os.Symlink(worktree, alias); err != nil {
				t.Fatal(err)
			}
			for i, command := range []string{"claude", "opencode --model 'a b'", "codex"} {
				f.clearCalls()
				var err error
				if i < 2 {
					err = f.launchIn("rex", "feature/x.y", command)
				} else {
					err = muxOpenWorktree(alias, "feature/x.y", command)
				}
				if err != nil {
					t.Fatal(err, f.stderr.String())
				}
				checkCalls(t, f.rexCalls(), [][]string{
					{"ls", "--json"},
					{"window", "new", "-s", session(0), "-c", worktree, "--json", "--", "/bin/sh", "-c", command},
					{"do", "session.select", "session_id=" + session(0), "window_id=" + windowID(i+1)},
				})
				want = append(want, rexWindow{session(0), windowID(i + 1)})
			}
			// A shell just shows the session.
			f.clearCalls()
			if err := f.switchIn("rex", "feature/x.y"); err != nil {
				t.Fatal(err, f.stderr.String())
			}
			checkCalls(t, f.rexCalls(), [][]string{{"ls", "--json"}, {"do", "session.select", "session_id=" + session(0)}})
			if !slices.Equal(f.windows(), want) || !slices.Equal(f.sessionIDs(), []string{session(0)}) {
				t.Errorf("sessions %q, windows %q", f.sessionIDs(), f.windows())
			}
		})
	}
}

func TestCommandTmuxTrailingSemicolon(t *testing.T) {
	// tmux takes an argument ending in ";" as a command separator, and drops a backslash before it.
	for _, c := range []struct{ command, want string }{
		{`find . -exec echo {} \;`, `find . -exec echo {} \\;`},
		{`echo a;`, `echo a\;`},
		{`;`, `\;`},
		{`echo a; echo b`, `echo a; echo b`},
		{`echo \; ok`, `echo \; ok`},
	} {
		for _, exists := range []bool{false, true} {
			t.Run(fmt.Sprintf("%q, session exists %t", c.command, exists), func(t *testing.T) {
				f := setup(t)
				setenv(t, inTmux)
				if exists {
					f.stub("tmux-has-session", "")
				}
				path := f.switchFeature()
				f.clearCalls()
				if err := f.launchIn("tmux", "feature/x.y", c.command); err != nil {
					t.Fatal(err, f.stderr.String())
				}
				open := []string{"tmux", "new-session", "-d", "-s", "feature_x_y", "-c", path, "/bin/sh", "-c", c.want}
				if exists {
					open = []string{"tmux", "new-window", "-t", "=feature_x_y:", "-c", path, "/bin/sh", "-c", c.want}
				}
				checkCalls(t, f.calls(), [][]string{
					{"tmux", "has-session", "-t", "=feature_x_y"},
					open,
					{"tmux", "switch-client", "-t", "=feature_x_y"},
				})
			})
		}
	}
}

func TestCommandTmuxSharedSessionOpensWhereSelected(t *testing.T) {
	f := setup(t)
	setenv(t, inTmux)
	f.git("branch", "topic")
	if err := f.switchIn("tmux", "topic"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	// The branch of another repository names the same session, which then exists.
	other := filepath.Join(f.root, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(other)
	f.git("init", "-q", "-b", "main")
	f.git("config", "user.name", "Test")
	f.git("config", "user.email", "test@example.com")
	f.git("commit", "-q", "--allow-empty", "-m", "base")
	f.git("branch", "topic")
	f.stub("tmux-has-session", "")
	f.clearCalls()
	if err := f.launchIn("tmux", "topic", "claude"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.calls(), [][]string{
		{"tmux", "has-session", "-t", "=topic"},
		{"tmux", "new-window", "-t", "=topic:", "-c", filepath.Join(other, "topic"), "/bin/sh", "-c", "claude"},
		{"tmux", "switch-client", "-t", "=topic"},
	})
}

func TestCommandRexWindowOpensWhereSelected(t *testing.T) {
	f, worktree, _ := rexFixture(t)
	// The worktree's session exists already; selecting it from another worktree adds the window at the selected one.
	if err := f.switchIn("rex", "feature/x.y"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	f.git("worktree", "add", "-q", "-b", "elsewhere", filepath.Join(f.root, "elsewhere"))
	t.Chdir(filepath.Join(f.root, "elsewhere"))
	f.clearCalls()
	if err := f.launchIn("rex", "feature/x.y", "claude"); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.rexCalls(), [][]string{
		{"ls", "--json"},
		{"window", "new", "-s", session(0), "-c", worktree, "--json", "--", "/bin/sh", "-c", "claude"},
		{"do", "session.select", "session_id=" + session(0), "window_id=" + windowID(1)},
	})
}

func TestCommandDefaultOnClone(t *testing.T) {
	f := setup(t)
	f.config(`{"default_command": "claude"}`)
	path := f.clone()
	checkCalls(t, f.calls(), [][]string{
		{"tmux", "has-session", "-t", "=main"},
		{"tmux", "new-session", "-s", "main", "-c", path, "/bin/sh", "-c", "claude"},
	})
}

func TestCommandTmuxFailuresAreNotShown(t *testing.T) {
	for _, inside := range []bool{false, true} {
		for _, failing := range []string{"new-error", "window-error"} {
			t.Run(fmt.Sprintf("inside tmux %t, %s", inside, failing), func(t *testing.T) {
				f := setup(t)
				if inside {
					setenv(t, inTmux)
				}
				if failing == "window-error" {
					f.stub("tmux-has-session", "")
				}
				f.stub(failing, "tmux: failed\n")
				f.git("branch", "feature/x.y")
				if err := switchToBranch("feature/x.y", "claude"); !errors.Is(err, errReported) {
					t.Fatalf("got %v", err)
				}
				var opened int
				for _, call := range f.calls() {
					switch call[1] {
					case "new-session", "new-window":
						opened++
					case "switch-client", "attach-session":
						t.Errorf("showed the session: %q", call)
					}
				}
				if opened != 1 || !isWorktree(filepath.Join(f.repo, "feature/x.y")) {
					t.Errorf("%d attempts, calls %q", opened, f.calls())
				}
			})
		}
	}
}

func TestCommandRexFailures(t *testing.T) {
	t.Run("uncertain session creation", func(t *testing.T) {
		f, worktree, label := rexFixture(t)
		f.stub("new-error", "Error: timed out\n")
		if err := f.launchIn("rex", "feature/x.y", "claude"); err != nil {
			t.Fatal(err, f.stderr.String())
		}
		// Never retried, nor a window added: the command may be running in the session created.
		checkCalls(t, f.rexCalls(), [][]string{
			{"ls", "--json"},
			{"new", label, "-c", worktree, "--json", "--", "/bin/sh", "-c", "claude"},
			{"ls", "--json"},
			{"do", "session.select", "session_id=" + session(0)},
		})
		if !slices.Equal(f.windows(), []rexWindow{{session(0), windowID(0)}}) {
			t.Errorf("windows %q", f.windows())
		}
	})

	t.Run("duplicate labels", func(t *testing.T) {
		f, _, label := rexFixture(t)
		f.stub("sessions.json", []map[string]string{{"session_id": "session:a", "label": label}, {"session_id": "session:b", "label": label}})
		if f.launchIn("rex", "feature/x.y", "claude") == nil || !strings.Contains(f.stderr.String(), "several sessions are labelled "+label) {
			t.Fatalf("stderr %q", f.stderr.String())
		}
		checkCalls(t, f.rexCalls(), [][]string{{"ls", "--json"}})
		if f.windows() != nil {
			t.Errorf("windows %q", f.windows())
		}
	})

	for _, c := range []struct {
		name, file, data, message string
		opened                    bool
	}{
		{"window not opened", "window-error", "Error: no such session\n", "can't open window in session %s: Error: no such session", false},
		{"window opened, then failed", "window-error-after", "Error: timed out\n", "can't open window in session %s: Error: timed out", true},
		{"invalid response", "window-output", "not json\n", "can't read rex window new response for session %s: invalid JSON or missing window_id", true},
		{"no window_id", "window-output", `{"block_ids": []}`, "can't read rex window new response for session %s: invalid JSON or missing window_id", true},
		{"window not shown", "do-error", "Error: The operation couldn't be completed.\n", "can't show session %s: Error: The operation couldn't be completed.", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, worktree, _ := rexFixture(t)
			if err := f.switchIn("rex", "feature/x.y"); err != nil {
				t.Fatal(err, f.stderr.String())
			}
			f.stub(c.file, c.data)
			f.clearCalls()
			if f.launchIn("rex", "feature/x.y", "claude") == nil {
				t.Fatal("succeeded")
			}
			want := fmt.Sprintf("wt: worktree ready at %s; Rex session could not be opened: "+c.message, worktree, session(0))
			if !strings.Contains(f.stderr.String(), want) {
				t.Errorf("stderr %q\nwant %q", f.stderr.String(), want)
			}
			// One attempt at the window, never retried, replaced by a new session, or shown unless it's known.
			calls := [][]string{{"ls", "--json"}, {"window", "new", "-s", session(0), "-c", worktree, "--json", "--", "/bin/sh", "-c", "claude"}}
			if c.file == "do-error" {
				calls = append(calls, []string{"do", "session.select", "session_id=" + session(0), "window_id=" + windowID(1)})
			}
			checkCalls(t, f.rexCalls(), calls)
			windows := []rexWindow{{session(0), windowID(0)}}
			if c.opened {
				windows = append(windows, rexWindow{session(0), windowID(1)})
			}
			if !slices.Equal(f.windows(), windows) || !slices.Equal(f.sessionIDs(), []string{session(0)}) {
				t.Errorf("sessions %q, windows %q", f.sessionIDs(), f.windows())
			}
			if !isWorktree(worktree) || !f.hasRef("refs/heads/feature/x.y") {
				t.Error("worktree or branch removed")
			}
		})
	}
}

// Setup command

// setupLogged is a wt.setupCommand that logs, among the stubs' calls, the worktree and branch it's given and
// the folder it runs in.
const setupLogged = `printf '["setup","%s","%s","%s"]\n' "$WT_WORKTREE" "$WT_BRANCH" "$(pwd -P)" >> "$WT_STUB_DIR/calls"`

func TestSetupCommandRunsOnceWhenTheWorktreeIsCreated(t *testing.T) {
	f := setup(t)
	f.git("config", "wt.setupCommand", setupLogged)
	path := f.switchFeature()
	open := []string{"tmux", "new-session", "-A", "-s", "feature_x_y", "-c", path}
	checkCalls(t, f.calls(), [][]string{{"setup", path, "feature/x.y", path}, open})
	// Switching to it again opens it as it is.
	f.clearCalls()
	if err := switchToBranch("feature/x.y [wt]", ""); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	checkCalls(t, f.calls(), [][]string{open})
}

func TestSetupCommandFailureKeepsWorktreeUnopened(t *testing.T) {
	f := setup(t)
	f.git("config", "wt.setupCommand", "exit 3")
	f.git("branch", "feature/x.y")
	if switchToBranch("feature/x.y", "") == nil {
		t.Fatal("succeeded")
	}
	worktree := filepath.Join(f.repo, "feature/x.y")
	if want := "wt: worktree ready at " + worktree + "; wt.setupCommand failed: exit status 3"; !strings.Contains(f.stderr.String(), want) {
		t.Errorf("stderr %q", f.stderr.String())
	}
	if !isWorktree(worktree) {
		t.Error("worktree removed")
	}
	checkCalls(t, f.calls(), nil)
}

func TestSetupCommandGlobalAndRepositoryValues(t *testing.T) {
	f := setup(t)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(f.root, "gitconfig"))
	f.git("config", "--global", "wt.setupCommand", "touch set-up")
	// The global value sets up every repository's new worktrees, the first one wt clone makes included.
	if path := f.clone(); !exists(filepath.Join(path, "set-up")) {
		t.Error("cloned worktree not set up")
	}
	t.Chdir(f.repo)
	if path := f.switchFeature(); !exists(filepath.Join(path, "set-up")) {
		t.Error("worktree not set up")
	}
	// An empty value in the repository turns the global one off.
	f.git("config", "wt.setupCommand", "")
	f.git("branch", "other")
	if err := switchToBranch("other", ""); err != nil {
		t.Fatal(err, f.stderr.String())
	}
	if exists(filepath.Join(f.repo, "other", "set-up")) {
		t.Error("set up despite the repository's empty value")
	}
}
