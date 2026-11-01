package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// gitTo runs git, its output going to stdout and stderr (nil discards it).
func gitTo(stdout, stderr io.Writer, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// gitOK runs git quietly and reports whether it succeeded.
func gitOK(args ...string) bool {
	return gitTo(nil, nil, args...) == nil
}

// gitRun runs git for the user to see, so its errors are already reported.
func gitRun(args ...string) error {
	if gitTo(os.Stdout, errOut, args...) != nil {
		return errReported
	}
	return nil
}

// gitOutput runs git and returns its output without the trailing newline. The error carries git's message.
func gitOutput(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
		err = errors.New(strings.TrimSpace(string(exitErr.Stderr)))
	}
	return strings.TrimRight(string(out), "\n"), err
}

// lines splits output into its non-empty lines.
func lines(out string) []string {
	return strings.FieldsFunc(out, func(r rune) bool { return r == '\n' })
}

// Per-repo state lives in the git common dir, under wt-state:
//
//	pending/<branch>          one marker per in-flight deletion (encoded branch name), containing
//	                          the PID of the process doing the deletion
//	sessions/<pid>            one file per open `wt` picker, containing its fzf --listen socket path,
//	                          so finished deletions can refresh every open picker
//	delete-error              why the last deletion failed
//	issues, prs, previews/    the GitHub cache (see github.go)
func stateDir(name string) (string, error) {
	common, err := gitOutput("rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return "", errors.New("not a git repository")
	}
	return filepath.Join(common, "wt-state", name), nil
}

// Branch names may contain '/', so they're encoded into flat file names.
func encodeBranch(branch string) string {
	return strings.ReplaceAll(strings.ReplaceAll(branch, "%", "%25"), "/", "%2F")
}

func decodeBranch(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "%2F", "/"), "%25", "%")
}

type worktree struct {
	path   string
	branch string // its full ref, if a branch is checked out
	bare   bool
}

func worktrees() []worktree {
	out, _ := gitOutput("worktree", "list", "--porcelain")
	var list []worktree
	for _, line := range lines(out) {
		if path, ok := strings.CutPrefix(line, "worktree "); ok {
			list = append(list, worktree{path: path})
		} else if len(list) == 0 {
			continue
		} else if ref, ok := strings.CutPrefix(line, "branch "); ok {
			list[len(list)-1].branch = ref
		} else if line == "bare" {
			list[len(list)-1].bare = true
		}
	}
	return list
}

// worktreeOf finds the path of the worktree that has branch checked out.
func worktreeOf(branch string) string {
	for _, w := range worktrees() {
		ref := strings.TrimPrefix(w.branch, "refs/heads/")
		ref = strings.TrimPrefix(ref, "refs/remotes/origin/")
		if w.branch != "" && ref == branch {
			return w.path
		}
	}
	return ""
}

// worktreeBranches is the set of branches checked out in a worktree.
func worktreeBranches() map[string]bool {
	set := map[string]bool{}
	for _, w := range worktrees() {
		if w.branch != "" {
			set[strings.TrimPrefix(w.branch, "refs/heads/")] = true
		}
	}
	return set
}

// localBranches is the set of local branch names.
func localBranches() map[string]bool {
	out, _ := gitOutput("for-each-ref", "--format=%(refname:lstrip=2)", "refs/heads")
	set := map[string]bool{}
	for _, b := range lines(out) {
		set[b] = true
	}
	return set
}
