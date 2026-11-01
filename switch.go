package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const pendingSuffix = " [deleting…]"

// defaultBranchRef finds the default branch without a network request. It prefers the remote-tracking
// ref, so a stale local main doesn't hide merges already fetched.
func defaultBranchRef() (string, bool) {
	head, _ := gitOutput("symbolic-ref", "--quiet", "refs/remotes/origin/HEAD")
	for _, ref := range []string{head, "refs/remotes/origin/main", "refs/remotes/origin/master", "refs/heads/main", "refs/heads/master"} {
		if ref != "" && gitOK("rev-parse", "--verify", "--quiet", ref+"^{commit}") {
			return ref, true
		}
	}
	return "", false
}

// listBranches lists the branches for the picker as branch/status<TAB>metadata<TAB>full ref (hidden in fzf),
// marking active worktrees [wt] and remote-only entries. Local tips take precedence over origin tips.
// Symbolic remote HEAD refs and the current branch are left out. Worktrees come first, then the branches
// with a deletion in flight, tagged as deleting, then the rest.
func listBranches() []string {
	merged := map[string]bool{}
	if target, ok := defaultBranchRef(); ok {
		out, _ := gitOutput("for-each-ref", "--merged="+target, "--format=%(objectname)", "refs/heads", "refs/remotes")
		for _, object := range lines(out) {
			merged[object] = true
		}
	}
	inWorktree := worktreeBranches()
	current, _ := gitOutput("branch", "--show-current")
	pending := map[string]bool{}
	for _, branch := range listPending() {
		pending[branch] = true
	}

	type branch struct{ name, age, object, ref string }
	var branches []branch
	seen := map[string]bool{}
	out, _ := gitOutput("for-each-ref", "--sort=refname",
		"--format=%(refname)%09%(committerdate:relative)%09%(objectname)%09%(symref)", "refs/heads", "refs/remotes")
	for _, line := range lines(out) {
		f := strings.Split(line, "\t")
		if len(f) != 4 || f[3] != "" {
			continue
		}
		name, local := strings.CutPrefix(f[0], "refs/heads/")
		if !local {
			name = strings.TrimPrefix(strings.TrimPrefix(f[0], "refs/remotes/"), "origin/")
		}
		if !seen[name] {
			seen[name] = true
			branches = append(branches, branch{name, f[1], f[2], f[0]})
		}
	}
	sort.Slice(branches, func(i, j int) bool { return branches[i].name < branches[j].name })

	var active, deleting, rest []string
	for _, b := range branches {
		if b.name == current || b.name == "" {
			continue
		}
		meta := "\t"
		if remote, ok := strings.CutPrefix(b.ref, "refs/remotes/"); ok {
			meta += "\033[36m[remote-only: " + remote + "]\033[0m  "
		}
		if merged[b.object] {
			meta += "\033[32m[merged]\033[0m  "
		}
		meta += "\033[2mlast commit: " + b.age + "\033[0m\t" + b.ref
		switch {
		case pending[b.name]:
			deleting = append(deleting, b.name+"\033[33m"+pendingSuffix+"\033[0m"+meta)
		case inWorktree[b.name]:
			active = append(active, b.name+" [wt]"+meta)
		default:
			rest = append(rest, b.name+meta)
		}
	}
	return append(append(active, deleting...), rest...)
}

// header is the branch picker's header, including the number of in-flight deletions and why the last one failed.
func header() string {
	var b strings.Builder
	b.WriteString("Ctrl-X: Delete local branch/worktree; remote-only: confirm remote deletion")
	if target, ok := defaultBranchRef(); ok {
		target = strings.TrimPrefix(strings.TrimPrefix(target, "refs/remotes/"), "refs/heads/")
		fmt.Fprintf(&b, "   [merged]: in %s", target)
	}
	if n := len(listPending()); n > 0 {
		fmt.Fprintf(&b, "   ⏳ Deleting %d branch(es)…", n)
	}
	if file, err := stateDir("delete-error"); err == nil {
		if data, err := os.ReadFile(file); err == nil && len(data) > 0 {
			fmt.Fprintf(&b, "\n⚠ %s", strings.TrimRight(string(data), "\n"))
		}
	}
	return b.String()
}

// cmdSwitch lists all branches and switches to the one picked, or to the new branch typed in, with the
// command the key pressed picks.
func cmdSwitch() error {
	if _, err := muxSetting(); err != nil {
		return err
	}
	cfg, err := loadCommandConfig()
	if err != nil {
		return err
	}
	branch, command, err := pickBranch(cfg)
	if err != nil {
		return err
	}
	return switchToBranch(branch, command)
}

// pickBranch shows the branch picker, returning the branch picked (or the new one typed in) and the
// command to open it with. Ctrl-X starts a background deletion and returns straight away, so several
// deletions can run at once. The picker registers its fzf --listen socket so finished deletions can make it
// reload, and its header is refreshed after every (re)load.
func pickBranch(cfg commandConfig) (string, string, error) {
	sockDir, err := os.MkdirTemp("", "wt.")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "fzf.sock")
	if sessions, err := stateDir("sessions"); err == nil && os.MkdirAll(sessions, 0o755) == nil {
		file := filepath.Join(sessions, strconv.Itoa(os.Getpid()))
		if os.WriteFile(file, []byte(sock+"\n"), 0o644) == nil {
			defer os.Remove(file)
		}
	}
	wt := shellQuote(self())
	return pickLaunch(listBranches(), cfg, cfg.DefaultCommand, true, "--ansi", "--prompt=Branch> ", "--listen="+sock,
		"--header="+header(), "--delimiter=\t", "--with-nth=1,2",
		"--bind=ctrl-x:execute("+wt+" --delete-selected {3} {1})+reload-sync("+wt+" --list-branches)",
		"--bind=load:transform-header("+wt+" --header)")
}

// switchToBranch takes a branch picked in fzf (possibly tagged [wt] or deleting, with the picker's other
// fields) and switches to its multiplexer session, creating the worktree - and the branch, off a freshly
// fetched origin/<default> - when missing. A command opens instead of a shell.
func switchToBranch(picked, command string) error {
	branch, fields, _ := strings.Cut(picked, "\t")
	// The hidden ref identifies remote-only selections, including non-origin remotes.
	remoteRef := ""
	if _, ref, ok := strings.Cut(fields, "\t"); ok && strings.HasPrefix(ref, "refs/remotes/") {
		remoteRef = ref
	}
	if name, ok := strings.CutSuffix(branch, pendingSuffix); ok {
		fmt.Fprintf(errOut, "wt: '%s' is being deleted\n", name)
		return errReported
	}
	branch = strings.TrimSuffix(branch, " [wt]")
	if remoteRef != "" {
		_, branch, _ = strings.Cut(strings.TrimPrefix(remoteRef, "refs/remotes/"), "/")
	}
	if branch == "" {
		return nil
	}
	if !gitOK("check-ref-format", "--branch", branch) {
		return errReported
	}
	if err := muxPreflight(); err != nil {
		return err
	}

	commonDir, err := gitOutput("rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return errReported
	}
	// Worktrees sit next to the repository: beside .git, or inside the directory holding a bare one.
	root := commonDir
	for _, w := range worktrees() {
		if w.bare && w.path == commonDir {
			root = w.path
			break
		}
	}
	path := filepath.Join(filepath.Dir(root), branch)

	if existing := worktreeOf(branch); existing != "" {
		path = existing
	} else if !isWorktree(path) {
		if err := addWorktree(path, branch, remoteRef); err != nil {
			return err
		}
		if err := setUpWorktree(path, branch); err != nil {
			return err
		}
	}
	return muxOpenWorktree(path, branch, command)
}

func isWorktree(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir() && gitOK("-C", path, "rev-parse", "--is-inside-work-tree")
}

// addWorktree creates the worktree for branch at path. A branch that's neither local nor picked from a
// remote is created off the latest origin/<default> (or the last fetched one when offline), without
// tracking it, so the first push sets up origin/<branch>.
func addWorktree(path, branch, remoteRef string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if gitOK("show-ref", "--verify", "--quiet", "refs/heads/"+branch) {
		return gitRun("worktree", "add", path, branch)
	}
	if remoteRef != "" {
		return gitRun("worktree", "add", "--track", "-b", branch, path, remoteRef)
	}
	// git guesses an existing branch here, such as one on the remote
	if gitTo(os.Stdout, nil, "worktree", "add", path, branch) == nil {
		return nil
	}
	base, _ := gitOutput("symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
	base = strings.TrimPrefix(base, "origin/")
	local := localBranches()
	for _, name := range []string{"main", "master"} {
		if base == "" && local[name] {
			base = name
		}
	}
	if gitTo(nil, errOut, "fetch", "--quiet", "origin", base) != nil {
		fmt.Fprintf(errOut, "wt: fetch failed, branching from last known origin/%s\n", base)
	}
	start := "origin/" + base
	if !gitOK("rev-parse", "--verify", "--quiet", start+"^{commit}") {
		start = base
	}
	return gitRun("worktree", "add", "--no-track", "-b", branch, path, start)
}

// setUpWorktree runs the repository's wt.setupCommand, a shell snippet, in the worktree wt has just created
// at path, on branch, and in wt's terminal, before the worktree opens. git config picks the value: the
// repository's over the user's global one, so an empty one in the repository turns a global one off. The
// worktree comes in WT_WORKTREE and WT_BRANCH. When the command fails the worktree stays, unopened.
func setUpWorktree(path, branch string) error {
	setup, err := gitOutput("-C", path, "config", "--get", "wt.setupCommand")
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return nil // unset: git config says nothing, it only exits with 1
	}
	if err != nil {
		wtError(fmt.Sprintf("worktree ready at %s; can't read wt.setupCommand: %v", path, err))
		return errReported
	}
	if strings.TrimSpace(setup) == "" {
		return nil
	}
	fmt.Printf("Running wt.setupCommand in '%s'...\n", path)
	cmd := exec.Command("/bin/sh", "-c", setup)
	cmd.Dir = path
	cmd.Env = append(cmd.Environ(), "WT_WORKTREE="+path, "WT_BRANCH="+branch)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		wtError(fmt.Sprintf("worktree ready at %s; wt.setupCommand failed: %v", path, err))
		return errReported
	}
	return nil
}

// cmdClone clones a repository as bare, into <dir>/.bare, and opens a worktree of its default branch.
func cmdClone(url, dir string) error {
	if url == "" {
		fmt.Fprintln(errOut, "Usage: wt clone <repo_url> [<directory>]")
		return errReported
	}
	if dir == "" {
		dir = repoName(url)
	}
	if _, err := os.Stat(dir); err == nil {
		fmt.Fprintf(errOut, "Error: Target directory '%s' already exists.\n", dir)
		return errReported
	}
	cfg, err := loadCommandConfig()
	if err != nil {
		return err
	}
	if err := muxPreflight(); err != nil {
		return err
	}

	fmt.Printf("Cloning bare repository into '%s/.bare'...\n", dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	dir, err = filepath.Abs(dir)
	if err == nil {
		dir, err = filepath.EvalSymlinks(dir)
	}
	if err != nil {
		return err
	}
	if err := gitRun("-C", dir, "clone", "--bare", url, ".bare"); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: ./.bare\n"), 0o644); err != nil {
		return err
	}
	if err := gitRun("-C", dir, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"); err != nil {
		return err
	}
	branch, _ := gitOutput("--git-dir="+filepath.Join(dir, ".bare"), "symbolic-ref", "--short", "HEAD")
	if branch = strings.TrimPrefix(branch, "refs/heads/"); branch == "" {
		branch = "main"
	}
	fmt.Printf("Creating first worktree for branch '%s'...\n", branch)
	if err := gitRun("-C", dir, "worktree", "add", branch); err != nil {
		return err
	}
	path := filepath.Join(dir, branch)
	if err := setUpWorktree(path, branch); err != nil {
		return err
	}
	return muxOpenWorktree(path, branch, cfg.DefaultCommand)
}

// repoName is the name a clone of url gets: its last path component, without .git.
func repoName(url string) string {
	name := strings.TrimSuffix(url, ".git")
	name = name[strings.LastIndex(name, "/")+1:]
	return name[strings.LastIndex(name, ":")+1:]
}
