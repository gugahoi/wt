# wt

`wt` is a Git worktree manager for the terminal. It picks branches, GitHub issues, and pull requests with fzf, creates worktrees on demand, and opens each one in its own tmux, Zellij, or Rex session, or with a command of your own.

## Install

```sh
brew install gugahoi/tap/wt
```

Or download the binary for your platform (macOS or Linux, arm64 or amd64) from the [latest release](https://github.com/gugahoi/wt/releases/latest) and put `wt` on your `PATH`.

`wt` is a single binary with fzf built in. It runs `git`, and tmux, Zellij, or Rex to open sessions. `wt issue` and `wt pr` log in to GitHub with `GH_TOKEN`, or with `gh` if it's installed and logged in.

## Usage

```
wt - Git Worktree Manager with tmux, Zellij and Rex integration

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
           REX_CLIENT picks the Rex app when several are connected.
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
```

### Other multiplexers

`WT_MULTIPLEXER=command` opens worktrees with any tool that has a command line. Pass the worktree through the variables, never by pasting it into the command, so that branch names stay data. `WT_COMMAND` is the command to open it with, a shell snippet for `sh -c`, or empty to open a shell; it's always set, so that an inherited one is never taken for it, and it's data too: run it as `/bin/sh -c "$WT_COMMAND"`, never pasted into the command. The examples that don't use it open a shell whatever the command:

```sh
export WT_MULTIPLEXER=command

# a tmux window rather than a session, running the command when there is one
export WT_OPEN_COMMAND='tmux new-window -n "$WT_BRANCH" -c "$WT_WORKTREE" ${WT_COMMAND:+/bin/sh -c "$WT_COMMAND"}'

# a WezTerm workspace (a new window each time: wezterm cli can't switch to an existing one)
export WT_OPEN_COMMAND='wezterm cli spawn --new-window --workspace "$WT_SESSION" --cwd "$WT_WORKTREE"'

# a kitty tab (needs allow_remote_control in kitty.conf)
export WT_OPEN_COMMAND='kitten @ launch --type=tab --tab-title "$WT_BRANCH" --cwd "$WT_WORKTREE"'
```

## Development

```sh
go test ./...
go build
```

The tests need `git`; tmux, Zellij, and Rex are stubbed.

## Releasing

```sh
git tag vX.Y.Z && git push origin vX.Y.Z
```

Or run the Release workflow from the Actions tab with a tag. It builds the binaries with `scripts/build-release.sh`, attaches them to the GitHub Release, and writes `Formula/wt.rb` in [gugahoi/homebrew-tap](https://github.com/gugahoi/homebrew-tap) with `scripts/write-formula.sh`.
