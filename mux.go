package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
)

// WT_MULTIPLEXER picks the terminal multiplexer worktrees open in: tmux, rex, or auto (the default) - tmux
// inside tmux, Rex inside a live Rex session, and tmux otherwise. Only commands that open a worktree resolve
// it, so listing, deletion and the fzf helpers need neither tmux nor rex.

// mux is the multiplexer worktrees open in, once muxPreflight has picked and checked it.
var mux string

// muxSetting checks WT_MULTIPLEXER, so that a typo fails before any picker shows.
func muxSetting() error {
	switch setting := os.Getenv("WT_MULTIPLEXER"); setting {
	case "", "auto", "tmux", "rex":
		return nil
	default:
		wtError(fmt.Sprintf("WT_MULTIPLEXER must be auto, tmux or rex, not '%s'", setting))
		return errReported
	}
}

// muxPreflight picks the multiplexer and checks it can open a worktree, before wt changes anything.
// An inherited REX_SESSION can be stale, so it only counts once the server confirms it (without starting a
// server). A multiplexer that's been picked is never swapped for the other when it fails.
func muxPreflight() error {
	if mux != "" {
		return nil
	}
	if err := muxSetting(); err != nil {
		return err
	}
	picked := os.Getenv("WT_MULTIPLEXER")
	if picked == "" || picked == "auto" {
		picked = "tmux"
		if os.Getenv("TMUX") == "" && os.Getenv("REX_SESSION") != "" && rexLive() {
			picked = "rex"
		}
	}
	if picked == "tmux" {
		if _, err := exec.LookPath("tmux"); err != nil {
			wtError("tmux not found")
			return errReported
		}
	} else {
		if _, err := exec.LookPath("rex"); err != nil {
			wtError("opening worktrees in Rex needs rex")
			return errReported
		}
		out, err := exec.Command("rex", "--autostart=false", "client", "inspect", "--json").CombinedOutput()
		if err != nil {
			wtError("no Rex app to open worktrees in (REX_CLIENT picks one): " + strings.TrimRight(string(out), "\n"))
			return errReported
		}
		var client struct{ Actions []struct{ Name string } }
		canSelect := false
		if json.Unmarshal(out, &client) == nil {
			for _, action := range client.Actions {
				canSelect = canSelect || action.Name == "session.select"
			}
		}
		if !canSelect {
			wtError("the Rex app can't show sessions (no session.select action)")
			return errReported
		}
	}
	mux = picked
	return nil
}

// rexLive tells whether the server knows the Rex session wt runs in.
func rexLive() bool {
	out, err := exec.Command("rex", "--autostart=false", "whoami", "--json").Output()
	var whoami struct {
		SessionID *string `json:"session_id"`
	}
	return err == nil && json.Unmarshal(out, &whoami) == nil && whoami.SessionID != nil
}

// muxOpenWorktree opens the worktree at path, on branch, in the multiplexer: a shell, reusing the worktree's
// session, or else command, in a new window of that session (or the first window of a new one). The
// worktree stays when that fails; tmux reports its own errors.
func muxOpenWorktree(path, branch, command string) error {
	if err := muxPreflight(); err != nil {
		return err
	}
	if mux == "tmux" {
		return tmuxOpen(path, branch, command)
	}
	if err := rexOpen(path, branch, command); err != nil {
		wtError(fmt.Sprintf("worktree ready at %s; Rex session could not be opened: %v", path, err))
		return errReported
	}
	return nil
}

// tmuxOpen switches to (or, outside tmux, attaches) the tmux session named after the branch, creating it in
// the worktree. Names don't include the repository, so the same branch in two repositories shares one.
// A command runs in a new window of the session, or in the first window of the session it creates.
func tmuxOpen(path, branch, command string) error {
	session := strings.NewReplacer("/", "_", ".", "_", ":", "_").Replace(branch)
	tmux := func(args ...string) error {
		cmd := exec.Command("tmux", args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if cmd.Run() != nil {
			return errReported
		}
		return nil
	}
	inside := os.Getenv("TMUX") != ""
	window := []string{"-c", path}
	if command != "" {
		window = append(window, "/bin/sh", "-c", command)
	}
	if command == "" && !inside {
		return tmux(append([]string{"new-session", "-A", "-s", session}, window...)...)
	}
	exists := exec.Command("tmux", "has-session", "-t", "="+session).Run() == nil
	if !exists && !inside {
		// Attached as it's created: -A would attach to a session created since the check, without the command.
		return tmux(append([]string{"new-session", "-s", session}, window...)...)
	}
	var err error
	if !exists {
		err = tmux(append([]string{"new-session", "-d", "-s", session}, window...)...)
	} else if command != "" {
		// The trailing colon picks the session's next free window index.
		err = tmux(append([]string{"new-window", "-t", "=" + session + ":"}, window...)...)
	}
	if err != nil {
		return err
	}
	if inside {
		return tmux("switch-client", "-t", "="+session)
	}
	return tmux("attach-session", "-t", "="+session)
}

// rexOpen shows the worktree's Rex session (one per worktree), creating it in the worktree when there's
// none. Sessions are found by their exact label, so a renamed one is no longer reused. A command runs in a
// new window of the session, shown, or in the first window of the session it creates.
func rexOpen(path, branch, command string) error {
	resolved, err := filepath.Abs(path)
	if err == nil {
		resolved, err = filepath.EvalSymlinks(resolved)
	}
	if err != nil {
		return fmt.Errorf("can't resolve %s", path)
	}
	path = resolved
	label := rexLabel(path, branch)
	ids, err := rexSessions(label)
	if err != nil {
		return err
	}
	if len(ids) == 1 && command != "" {
		return rexOpenWindow(ids[0], path, command)
	}
	if len(ids) == 0 {
		args := []string{"new", label, "-c", path, "--json"}
		if command != "" {
			args = append(args, "--", "/bin/sh", "-c", command)
		}
		out, err := exec.Command("rex", args...).CombinedOutput()
		var created struct {
			SessionID string `json:"session_id"`
		}
		if err == nil && json.Unmarshal(out, &created) == nil && created.SessionID != "" {
			ids = []string{created.SessionID}
		} else {
			// rex new may have created the session, and started its command, even though it failed or timed
			// out: look again rather than retry
			if ids, err = rexSessions(label); err != nil {
				return err
			}
			if len(ids) == 0 {
				if msg := strings.TrimRight(string(out), "\n"); msg != "" {
					return errors.New(msg)
				}
				return errors.New("rex new failed")
			}
		}
	}
	if len(ids) > 1 {
		return fmt.Errorf("several sessions are labelled %s: %s", label, strings.Join(ids, ", "))
	}
	return rexSelect(ids[0])
}

// rexOpenWindow runs command in a new window of the session, in the worktree at path, and shows it. A
// failed or unreadable rex window new may still have started the command, so it's never retried.
func rexOpenWindow(id, path, command string) error {
	out, err := exec.Command("rex", "window", "new", "-s", id, "-c", path, "--json", "--", "/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		return fmt.Errorf("can't open window in session %s: %s", id, strings.TrimRight(string(out), "\n"))
	}
	var window struct {
		WindowID string `json:"window_id"`
	}
	if json.Unmarshal(out, &window) != nil || window.WindowID == "" {
		return fmt.Errorf("can't read rex window new response for session %s: invalid JSON or missing window_id", id)
	}
	return rexSelect(id, "window_id="+window.WindowID)
}

// rexSelect shows the session in the Rex app, at the given window_id=<id> when there is one.
func rexSelect(id string, window ...string) error {
	args := append([]string{"do", "session.select", "session_id=" + id}, window...)
	if out, err := exec.Command("rex", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("can't show session %s: %s", id, strings.TrimRight(string(out), "\n"))
	}
	return nil
}

// rexSessions lists the IDs of the Rex sessions labelled exactly label.
func rexSessions(label string) ([]string, error) {
	out, err := exec.Command("rex", "ls", "--json").CombinedOutput()
	if err != nil {
		return nil, errors.New(strings.TrimRight(string(out), "\n"))
	}
	var list struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
			Label     string
		}
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("can't read rex ls: %w", err)
	}
	var ids []string
	for _, s := range list.Sessions {
		if s.Label == label {
			ids = append(ids, s.SessionID)
		}
	}
	return ids, nil
}

// rexLabel names the Rex session of the worktree at canonical path, on branch, <repo>-<branch>-<path hash>:
// the hash tells apart the same branch in two repositories, and is kept whole when a long name is cut to
// fit Rex's 128-character labels. The hash is git's object ID of the path, as `git hash-object` gives it.
func rexLabel(path, branch string) string {
	common, _ := gitOutput("-C", path, "rev-parse", "--path-format=absolute", "--git-common-dir")
	repo := common[:max(strings.LastIndex(common, "/"), 0)]
	name := []rune(repo[strings.LastIndex(repo, "/")+1:] + "-" + branch)
	for i, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("._-", r) {
			name[i] = '_'
		}
	}
	hash := sha1.Sum([]byte(fmt.Sprintf("blob %d\x00%s", len(path), path)))
	return string(name[:min(len(name), 100)]) + "-" + hex.EncodeToString(hash[:])[:10]
}
