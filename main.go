// Command wt is a Git worktree manager for the terminal. It picks branches, GitHub issues and pull requests
// with fzf, creates worktrees on demand, and opens each one in its own tmux, Zellij or Rex session, or with a
// command of the user's.
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

// errCancelled stops opening a worktree when the Rex app picker is dismissed, without reporting a failure.
var errCancelled = errors.New("cancelled")

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
	case "issue":
		if n := arg(1); n != "" {
			err = cmdIssue(n)
		} else {
			err = cmdGitHub("issue")
		}
	case "pr":
		if n := arg(1); n != "" {
			err = cmdPR(n)
		} else {
			err = cmdGitHub("pr")
		}
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
	if errors.Is(err, errCancelled) {
		return 0
	}
	if err != nil {
		if !errors.Is(err, errReported) {
			wtError(err.Error())
		}
		return 1
	}
	return 0
}

const help = `wt - Git Worktree Manager with tmux, Zellij and Rex integration

Usage:
  wt                  Interactively select a branch to switch to (creating worktree if needed)
                      - Press [Ctrl-x] inside the selection menu to delete the worktree and branch
                        (local deletions run in the background; remote-only entries require confirmation)
  wt issue [number]   Pick an open GitHub issue (newest first), or take the numbered one, and switch to (or create)
                      a <number>-* branch for it
  wt pr [number]      Pick an open GitHub pull request (ready first, then drafts; newest first), or take the
                      numbered one, and switch to its branch
                      - Press [Ctrl-t] inside either picker to switch between issues and pull requests
  wt clone <url> [dir] Clone a repository as bare and set up worktrees
  wt rm | delete      Interactively select a worktree to remove (with a confirmation prompt)
  wt list             List all active worktrees
  wt -h | --help      Show this help documentation

GitHub (wt issue, wt pr):
  The repository is the one gh would use (GH_REPO, or the git remotes). The token comes from GH_TOKEN or
  GITHUB_TOKEN, or else from gh's login (gh auth login).

Multiplexer (WT_MULTIPLEXER=auto | tmux | zellij | rex | command):
  auto, the default, opens worktrees in the first multiplexer wt runs inside: tmux ($TMUX), Zellij ($ZELLIJ),
  then Rex ($REX_SESSION, confirmed with the Rex server); otherwise in tmux, creating or attaching its
  session. tmux or Zellij inside Rex picks them; set WT_MULTIPLEXER=rex for Rex. A picked multiplexer that
  fails is reported, never swapped for another, and the worktree it was opening is kept.
  tmux     One session per branch, named after it; the same branch in two repositories shares one.
  zellij   One session per worktree, labelled <repo>-<branch>-<path hash> cut to at most 24 bytes, fewer
           when Zellij's socket folder is long, so the socket path fits; a renamed session is no longer
           reused. Switching sessions from inside Zellij, and opening a command (even outside Zellij), need
           zellij 0.44 or later; a session created for a command has it in its first tab from 0.45.1, and
           a shell tab first before.
  rex      Needs rex (without it, auto picks tmux even inside Rex). One session per worktree,
           labelled <repo>-<branch>-<path hash>; a renamed session is no longer reused.
           When several Rex apps are connected, wt asks which one to show the worktree in;
           Esc cancels without creating a worktree. REX_CLIENT selects an app by label or ID
           (see rex client ls) without asking; set it when running without an interactive terminal.
  command  Runs WT_OPEN_COMMAND with sh, in the worktree and wt's terminal, with WT_WORKTREE (its path),
           WT_BRANCH, WT_SESSION (a <repo>-<branch>-<path hash> label) and WT_COMMAND (the command to run
           there, empty to open a shell) set. Never picked by auto.
  Deleting a worktree leaves its session running, and a worktree recreated at the same path reuses it.

Commands ($XDG_CONFIG_HOME/wt/config.json, or ~/.config/wt/config.json):
  {"default_command": "claude", "keymaps": {"ctrl-a": "claude", "ctrl-o": "opencode"}}
  Enter opens the picked worktree with default_command, and a key in keymaps (an fzf key name) with its
  command, in the pickers of wt, wt issue and wt pr; wt clone opens with default_command. In tmux, Zellij
  and Rex a command runs with /bin/sh -c in the worktree, in a new window (in Zellij, tab) of the
  worktree's session, or in the first window of a new one; with no command, wt opens a shell, reusing the
  session. WT_MULTIPLEXER=command passes it in WT_COMMAND. Enter, Esc, Ctrl-C, Ctrl-G, Ctrl-X and Ctrl-T
  can't be mapped.

Setup (git config wt.setupCommand):
  git config wt.setupCommand 'pnpm install' sets a command wt runs in every worktree of the repository it
  creates (wt, wt issue and wt pr), before opening it; --global sets it for every repository, wt clone
  included, and an empty value in a repository turns a global one off. It runs with /bin/sh -c in the
  worktree and wt's terminal, with WT_WORKTREE and WT_BRANCH set. When it fails, wt reports it and keeps
  the worktree unopened; a worktree that exists already isn't set up again. On a pull request's branch,
  an install command runs that branch's install scripts.
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
