# wt

`wt` is a Git worktree manager for the terminal. It picks branches, GitHub issues, and pull requests with fzf, creates worktrees on demand, and opens each one in its own tmux or Rex session.

## Install

```sh
brew install gugahoi/tap/wt
```

Dependencies: `git`, `fzf` and `gh` are required; `tmux`, or Rex plus `jq`, is needed to open sessions.

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

Multiplexer (WT_MULTIPLEXER=auto | tmux | rex):
  auto, the default, opens worktrees in tmux inside tmux ($TMUX), in Rex inside a live Rex session
  ($REX_SESSION, confirmed with the Rex server), and otherwise in tmux, creating or attaching its session.
  tmux inside Rex picks tmux; set WT_MULTIPLEXER=rex for Rex. A picked multiplexer that fails is reported,
  never swapped for the other, and the worktree it was opening is kept.
  tmux  One session per branch, named after it; the same branch in two repositories shares one.
  Rex   Needs rex and jq (without them, auto picks tmux even inside Rex). One session per worktree,
        labelled <repo>-<branch>-<path hash>; a renamed session is no longer reused.
        REX_CLIENT picks the Rex app when several are connected.
  Deleting a worktree leaves its session running, and a worktree recreated at the same path reuses it.
```

## Tests

```sh
python3 -m unittest discover -s tests -p 'test_wt.py'
```

Requires `git`, `bash` and `jq`.

## Releasing

```sh
git tag vX.Y.Z && git push origin vX.Y.Z
```

The release workflow creates the GitHub Release and updates `Formula/wt.rb` in [gugahoi/homebrew-tap](https://github.com/gugahoi/homebrew-tap).
