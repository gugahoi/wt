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
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// WT_MULTIPLEXER picks the terminal multiplexer worktrees open in, by name, or auto (the default): the first
// of multiplexers that wt runs inside, and tmux otherwise. Only commands that open a worktree resolve it, so
// listing, deletion and the fzf helpers need no multiplexer.

// A multiplexer opens worktrees in sessions of its own.
type multiplexer struct {
	name  string // its WT_MULTIPLEXER value
	title string // its name in messages
	// inside tells whether wt runs in one of its sessions, for auto to pick it; nil when only picked by name.
	inside func() bool
	// check tells whether it can open a worktree now, before wt changes anything, reporting why not.
	check func() error
	// open opens the worktree at path, on branch. Its errors are reported with the worktree's path, unless
	// it has reported them itself (errReported).
	open func(path, branch string) error
}

// multiplexers are those WT_MULTIPLEXER names, in the order auto tries them: tmux and Zellij run inside
// terminal apps such as Rex, so they come first.
var multiplexers = []*multiplexer{
	{name: "tmux", title: "tmux", inside: func() bool { return os.Getenv("TMUX") != "" }, check: tmuxCheck, open: tmuxOpen},
	{name: "zellij", title: "Zellij", inside: func() bool { return os.Getenv("ZELLIJ") != "" }, check: zellijCheck, open: zellijOpen},
	{name: "rex", title: "Rex", inside: rexInside, check: rexCheck, open: rexOpen},
	{name: "command", title: "WT_OPEN_COMMAND", check: commandCheck, open: commandOpen},
}

// mux is the multiplexer worktrees open in, once muxPreflight has picked and checked it.
var mux *multiplexer

const (
	// rexLabelSize fits Rex's 128-character labels.
	rexLabelSize = 111
	// zellijLabelMax is the longest label a Zellij session gets: the 24 bytes that keep its socket,
	// $TMPDIR/zellij-<uid>/contract_version_1/<label>, within the 103 bytes macOS allows when $TMPDIR is the
	// usual 49 bytes (with its last slash) and the uid has 3 digits. A longer socket folder makes labels
	// shorter (zellijLabelSize), but a shorter one doesn't make them longer: sessions are found by name, so a
	// longer label would lose the sessions already open.
	zellijLabelMax = 24
	// labelSuffixSize is the size of the -<path hash> that ends every label: a dash and 10 hexadecimal digits.
	labelSuffixSize = 11
)

// muxSetting is the multiplexer WT_MULTIPLEXER names, or nil for auto. Commands check it before any picker
// shows, so that a typo fails first.
func muxSetting() (*multiplexer, error) {
	setting := os.Getenv("WT_MULTIPLEXER")
	if setting == "" || setting == "auto" {
		return nil, nil
	}
	names := []string{"auto"}
	for _, m := range multiplexers {
		if m.name == setting {
			return m, nil
		}
		names = append(names, m.name)
	}
	last := len(names) - 1
	wtError(fmt.Sprintf("WT_MULTIPLEXER must be %s or %s, not '%s'", strings.Join(names[:last], ", "), names[last], setting))
	return nil, errReported
}

// muxPreflight picks the multiplexer and checks it can open a worktree, before wt changes anything. A
// multiplexer that's been picked is never swapped for another when it fails.
func muxPreflight() error {
	if mux != nil {
		return nil
	}
	picked, err := muxSetting()
	if err != nil {
		return err
	}
	if picked == nil {
		picked = multiplexers[0]
		for _, m := range multiplexers {
			if m.inside != nil && m.inside() {
				picked = m
				break
			}
		}
	}
	if err := picked.check(); err != nil {
		return err
	}
	mux = picked
	return nil
}

// muxOpenWorktree opens the worktree at path, on branch, in the multiplexer. The worktree stays when that
// fails.
func muxOpenWorktree(path, branch string) error {
	if err := muxPreflight(); err != nil {
		return err
	}
	err := mux.open(path, branch)
	if err != nil && !errors.Is(err, errReported) {
		wtError(fmt.Sprintf("worktree ready at %s; %s session could not be opened: %v", path, mux.title, err))
		return errReported
	}
	return err
}

// canonical is path made absolute, with symlinks resolved, so that a worktree reached through a symlink
// opens the same session.
func canonical(path string) (string, error) {
	resolved, err := filepath.Abs(path)
	if err == nil {
		resolved, err = filepath.EvalSymlinks(resolved)
	}
	if err != nil {
		return "", fmt.Errorf("can't resolve %s", path)
	}
	return resolved, nil
}

// sessionLabel names the session of the worktree at canonical path, on branch, <repo>-<branch>-<path hash>,
// in at most size bytes, labelSuffixSize+utf8.UTFMax or more, to leave room for a whole character of the
// name. The hash tells apart the same branch in two repositories, and is kept whole when a long name is
// cut. The hash is git's object ID of the path, as `git hash-object` gives it.
func sessionLabel(path, branch string, size int) string {
	common, _ := gitOutput("-C", path, "rev-parse", "--path-format=absolute", "--git-common-dir")
	repo := common[:max(strings.LastIndex(common, "/"), 0)]
	name := []rune(repo[strings.LastIndex(repo, "/")+1:] + "-" + branch)
	for i, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("._-", r) {
			name[i] = '_'
		}
	}
	hash := sha1.Sum([]byte(fmt.Sprintf("blob %d\x00%s", len(path), path)))
	suffix := "-" + hex.EncodeToString(hash[:])[:labelSuffixSize-1]
	label := string(name)
	if cut := size - len(suffix); len(label) > cut {
		for cut > 0 && !utf8.RuneStart(label[cut]) {
			cut--
		}
		label = label[:cut]
	}
	return label + suffix
}

// tmux

// tmuxCheck checks tmux is there.
func tmuxCheck() error {
	if _, err := exec.LookPath("tmux"); err != nil {
		wtError("tmux not found")
		return errReported
	}
	return nil
}

// tmuxOpen switches to (or, outside tmux, attaches) the tmux session named after the branch, creating it in
// the worktree. Names don't include the repository, so the same branch in two repositories shares one.
// tmux reports its own errors.
func tmuxOpen(path, branch string) error {
	session := strings.NewReplacer("/", "_", ".", "_", ":", "_").Replace(branch)
	tmux := func(args ...string) error {
		cmd := exec.Command("tmux", args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	}
	var err error
	if os.Getenv("TMUX") != "" {
		if exec.Command("tmux", "has-session", "-t", "="+session).Run() != nil {
			err = tmux("new-session", "-d", "-s", session, "-c", path)
		}
		if err == nil {
			err = tmux("switch-client", "-t", "="+session)
		}
	} else {
		err = tmux("new-session", "-A", "-s", session, "-c", path)
	}
	if err != nil {
		return errReported
	}
	return nil
}

// Zellij

// pushPath appends elem to path, after a slash unless path is empty or ends in one, as Rust's PathBuf::push
// does for Zellij. filepath.Join would also clean the result, and Zellij limits the length of what it built.
func pushPath(path, elem string) string {
	if path == "" || strings.HasSuffix(path, "/") {
		return path + elem
	}
	return path + "/" + elem
}

// zellijSocketDir is the folder of Zellij's session sockets, found as Zellij finds it: $ZELLIJ_SOCKET_DIR,
// else the runtime folder, $XDG_RUNTIME_DIR/zellij, else zellij-<uid> in the temp folder; then
// contract_version_1 (zellij-utils/src/consts.rs:332-347 in v0.45.1, 282-297 in v0.44.0). The runtime folder
// is for an absolute $XDG_RUNTIME_DIR only, and macOS has none (directories crate, src/lin.rs:72 and
// src/mac.rs:82, the same in 5.0 as in 6.0).
func zellijSocketDir() string {
	dir, set := os.LookupEnv("ZELLIJ_SOCKET_DIR")
	if !set {
		if xdg := os.Getenv("XDG_RUNTIME_DIR"); runtime.GOOS != "darwin" && filepath.IsAbs(xdg) {
			dir = pushPath(xdg, "zellij")
		} else {
			dir = pushPath(os.TempDir(), "zellij-"+strconv.Itoa(os.Getuid()))
		}
	}
	return pushPath(dir, "contract_version_1")
}

// zellijLabelSize is the longest label a Zellij session can have: zellijLabelMax, or fewer bytes when the
// session's socket, <socket folder>/<label>, would reach the length Zellij turns down: 104 on macOS, 108
// elsewhere (zellij-client/src/lib.rs:357-372 and zellij-utils/src/consts.rs:325-329, v0.45.1). v0.44.0
// checks --session alone (zellij-utils/src/cli.rs:13-35), against 108 on macOS too, so a label that fits
// those limits fits it as well.
func zellijLabelSize() int {
	longest := 107
	if runtime.GOOS == "darwin" {
		longest = 103
	}
	return min(zellijLabelMax, longest-len(zellijSocketDir())-1)
}

// zellijVersion matches the output of zellij --version, as zellij 0.45.1, for its major and minor numbers.
var zellijVersion = regexp.MustCompile(`^zellij ([0-9]+)\.([0-9]+)`)

// zellijCheck checks zellij is there, that its socket folder leaves room for session names and, inside
// Zellij, that it can switch sessions from the command line, which came with Zellij 0.44.
func zellijCheck() error {
	if _, err := exec.LookPath("zellij"); err != nil {
		wtError("zellij not found")
		return errReported
	}
	// The name must keep a whole character: cut to nothing, the label would start with the hash's dash, which
	// Zellij's command line takes for an option.
	if zellijLabelSize() < labelSuffixSize+utf8.UTFMax {
		wtError("Zellij's socket folder " + zellijSocketDir() + " is too long for session names: set a shorter ZELLIJ_SOCKET_DIR")
		return errReported
	}
	if os.Getenv("ZELLIJ") == "" {
		return nil
	}
	out, _ := exec.Command("zellij", "--version").Output()
	version := strings.TrimSpace(string(out))
	var major, minor int
	if m := zellijVersion.FindStringSubmatch(version); m != nil {
		// Atoi only fails on a number too big for an int, and that is later than 0.44
		major, _ = strconv.Atoi(m[1])
		minor, _ = strconv.Atoi(m[2])
	}
	if major == 0 && minor < 44 {
		wtError("switching Zellij sessions needs zellij 0.44 or later, not '" + version + "'")
		return errReported
	}
	return nil
}

// zellijOpen switches to (or, outside Zellij, attaches) the worktree's Zellij session (one per worktree),
// creating it in the worktree when there's none. Sessions are found by name, so a renamed one is no longer
// reused. Attaching shows Zellij's own errors, and returns how it ended.
func zellijOpen(path, branch string) error {
	path, err := canonical(path)
	if err != nil {
		return err
	}
	session := sessionLabel(path, branch, zellijLabelSize())
	if os.Getenv("ZELLIJ") != "" {
		// switch-session creates a missing session in --cwd, and leaves an existing one as it is
		out, err := exec.Command("zellij", "action", "switch-session", session, "--cwd", path).CombinedOutput()
		if msg := strings.TrimRight(string(out), "\n"); err != nil && msg != "" {
			return errors.New(msg)
		}
		return err
	}
	// attach has no --cwd: a new session starts in the default cwd, which options sets over the
	// configuration's, or else in the directory zellij runs in. An existing session stays as it is.
	cmd := exec.Command("zellij", "attach", "--create", session, "options", "--default-cwd", path)
	cmd.Dir = path
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// Rex

// rexInside tells whether wt runs in a Rex session the server knows. An inherited REX_SESSION can be stale,
// so it only counts once the server confirms it (without starting a server).
func rexInside() bool {
	if os.Getenv("REX_SESSION") == "" {
		return false
	}
	out, err := exec.Command("rex", "--autostart=false", "whoami", "--json").Output()
	var whoami struct {
		SessionID *string `json:"session_id"`
	}
	return err == nil && json.Unmarshal(out, &whoami) == nil && whoami.SessionID != nil
}

// rexCheck checks there's a Rex app that can show sessions.
func rexCheck() error {
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
	return nil
}

// rexOpen shows the worktree's Rex session (one per worktree), creating it in the worktree when there's
// none. Sessions are found by their exact label, so a renamed one is no longer reused.
func rexOpen(path, branch string) error {
	path, err := canonical(path)
	if err != nil {
		return err
	}
	label := sessionLabel(path, branch, rexLabelSize)
	ids, err := rexSessions(label)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		out, err := exec.Command("rex", "new", label, "-c", path, "--json").CombinedOutput()
		var created struct {
			SessionID string `json:"session_id"`
		}
		if err == nil && json.Unmarshal(out, &created) == nil && created.SessionID != "" {
			ids = []string{created.SessionID}
		} else {
			// rex new may have created the session even though it failed or timed out: look again rather than retry
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
	if out, err := exec.Command("rex", "do", "session.select", "session_id="+ids[0]).CombinedOutput(); err != nil {
		return fmt.Errorf("can't show session %s: %s", ids[0], strings.TrimRight(string(out), "\n"))
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

// WT_OPEN_COMMAND

// commandCheck checks there's a WT_OPEN_COMMAND to run, and sh to run it with.
func commandCheck() error {
	if strings.TrimSpace(os.Getenv("WT_OPEN_COMMAND")) == "" {
		wtError("WT_MULTIPLEXER=command needs WT_OPEN_COMMAND")
		return errReported
	}
	if _, err := exec.LookPath("sh"); err != nil {
		wtError("running WT_OPEN_COMMAND needs sh")
		return errReported
	}
	return nil
}

// commandOpen runs WT_OPEN_COMMAND with sh, in the worktree and in wt's terminal. The worktree comes in
// WT_WORKTREE, WT_BRANCH and WT_SESSION rather than in the command's text, so that no branch name can change
// what it runs. The command reports its own errors; wt adds how it ended.
func commandOpen(path, branch string) error {
	dir, err := canonical(path)
	if err == nil {
		cmd := exec.Command("sh", "-c", os.Getenv("WT_OPEN_COMMAND"))
		cmd.Dir = dir
		cmd.Env = append(cmd.Environ(), "WT_WORKTREE="+dir, "WT_BRANCH="+branch, "WT_SESSION="+sessionLabel(dir, branch, rexLabelSize))
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		err = cmd.Run()
	}
	if err != nil {
		wtError(fmt.Sprintf("worktree ready at %s; WT_OPEN_COMMAND failed: %v", path, err))
		return errReported
	}
	return nil
}
