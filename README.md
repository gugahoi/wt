# wt

`wt` is a Git worktree manager for the terminal. It picks branches, GitHub issues, and pull requests with fzf, creates worktrees on demand, and opens each one in its own tmux or Rex session.

## Install

```sh
brew install gugahoi/tap/wt
```

Or download the binary for your platform (macOS or Linux, arm64 or amd64) from the [latest release](https://github.com/gugahoi/wt/releases/latest) and put `wt` on your `PATH`.

`wt` is a single binary with fzf built in. It runs `git`, and `tmux` or Rex to open sessions. `wt issue` and `wt pr` log in to GitHub with `GH_TOKEN`, or with `gh` if it's installed and logged in.

## Usage

```
wt - Git Worktree Manager with tmux and Rex integration

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

Commands ($XDG_CONFIG_HOME/wt/config.json, or ~/.config/wt/config.json):
  {"default_command": "claude", "keymaps": {"ctrl-a": "claude", "ctrl-o": "opencode"}}
  Enter opens the picked worktree with default_command, and a key in keymaps (an fzf key name) with its
  command, in the pickers of wt, wt issue and wt pr; wt clone opens with default_command. A command runs
  with /bin/sh -c in the worktree, in a new window of the worktree's session, or in the first window of a
  new one; with no command, wt opens a shell, reusing the session. Enter, Esc, Ctrl-C, Ctrl-G, Ctrl-X and
  Ctrl-T can't be mapped.
```

## Development

```sh
go test ./...
go build
```

The tests need `git`; tmux and Rex are stubbed.

## Releasing

```sh
git tag vX.Y.Z && git push origin vX.Y.Z
```

Or run the Release workflow from the Actions tab with a tag. It builds the binaries with `scripts/build-release.sh`, attaches them to the GitHub Release, and writes `Formula/wt.rb` in [gugahoi/homebrew-tap](https://github.com/gugahoi/homebrew-tap) with `scripts/write-formula.sh`.
