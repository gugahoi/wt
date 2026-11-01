// Command wt is a Git worktree manager for the terminal. It picks branches, GitHub issues and pull requests
// with fzf, creates worktrees on demand, and opens each one in its own tmux or Rex session.
//
// fzf runs in-process, but its key bindings and previews run commands: they call wt back through the
// hidden --flags below, so those are an interface between wt and the pickers it shows.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// errReported is returned once the user has been told what went wrong, so it needs no further message.
var errReported = errors.New("reported")

// errOut receives wt's errors and the output of the git commands it runs on the user's behalf.
var errOut io.Writer = os.Stderr

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	var err error
	switch arg(0) {
	case "--list-branches":
		printLines(listBranches())
	case "--delete-selected":
		_, err = deleteSelected(arg(1), arg(2))
	case "--delete-worker":
		deleteWorker(arg(1), arg(2))
	case "--header":
		fmt.Println(header())
	case "--lines":
		printLines(cmdLines(args[1:]))
	case "--toggle":
		fmt.Println(toggleActions())
	case "--preview":
		err = preview(arg(1), arg(2), arg(3))
	case "issue", "pr":
		err = cmdGitHub(arg(0))
	case "clone":
		err = cmdClone(arg(1), arg(2))
	case "rm", "delete":
		err = cmdDelete(os.Stdin)
	case "list":
		err = gitRun("worktree", "list")
	case "-h", "--help":
		fmt.Print(help)
	default:
		err = cmdSwitch()
	}
	if err != nil {
		if !errors.Is(err, errReported) {
			wtError(err.Error())
		}
		return 1
	}
	return 0
}

const help = `wt - Git Worktree Manager with tmux and Rex integration

Usage:
  wt                  Interactively select a branch to switch to (creating worktree if needed)
                      - Press [Ctrl-x] inside the selection menu to delete the worktree and branch
                        (local deletions run in the background; remote-only entries require confirmation)
  wt issue            Pick an open GitHub issue (newest first) and switch to (or create) a <number>-* branch for it
  wt pr               Pick an open GitHub pull request (ready first, then drafts; newest first) and switch to its branch
                      - Press [Ctrl-t] inside either picker to switch between issues and pull requests
  wt clone <url> [dir] Clone a repository as bare and set up worktrees
  wt rm | delete      Interactively select a worktree to remove (with a confirmation prompt)
  wt list             List all active worktrees
  wt -h | --help      Show this help documentation

GitHub (wt issue, wt pr):
  The repository is the one gh would use (GH_REPO, or the git remotes). The token comes from GH_TOKEN or
  GITHUB_TOKEN, or else from gh's login (gh auth login).

Multiplexer (WT_MULTIPLEXER=auto | tmux | rex):
  auto, the default, opens worktrees in tmux inside tmux ($TMUX), in Rex inside a live Rex session
  ($REX_SESSION, confirmed with the Rex server), and otherwise in tmux, creating or attaching its session.
  tmux inside Rex picks tmux; set WT_MULTIPLEXER=rex for Rex. A picked multiplexer that fails is reported,
  never swapped for the other, and the worktree it was opening is kept.
  tmux  One session per branch, named after it; the same branch in two repositories shares one.
  Rex   Needs rex (without it, auto picks tmux even inside Rex). One session per worktree,
        labelled <repo>-<branch>-<path hash>; a renamed session is no longer reused.
        REX_CLIENT picks the Rex app when several are connected.
  Deleting a worktree leaves its session running, and a worktree recreated at the same path reuses it.
`

// wtError reports an error on stderr and tmux's status line, since the popup closes as soon as wt exits.
func wtError(msg string) {
	line, _, _ := strings.Cut(msg, "\n")
	fmt.Fprintln(errOut, "wt: "+line)
	if os.Getenv("TMUX") != "" {
		exec.Command("tmux", "display-message", "wt: "+line).Run()
	}
}

func printLines(lines []string) {
	for _, line := range lines {
		fmt.Println(line)
	}
}

// self is the path of the wt binary, for the commands fzf runs to call it back.
func self() string {
	exe, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}

// shellQuote quotes s for the shell fzf runs its commands with.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
