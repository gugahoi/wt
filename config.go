package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	fzf "github.com/junegunn/fzf/src"
	"github.com/junegunn/fzf/src/tui"
)

// commandConfig is the user's $XDG_CONFIG_HOME/wt/config.json (~/.config/wt/config.json without it): the
// command a picked worktree opens with, and picker keys opening it with another. Commands are shell
// snippets, run by /bin/sh in the worktree; none opens a shell, reusing the worktree's session.
type commandConfig struct {
	DefaultCommand string            `json:"default_command"`
	Keymaps        map[string]string `json:"keymaps"`
}

// reservedKeys keep their picker actions: Enter opens with the default command, Esc, Ctrl-C and Ctrl-G
// cancel, Ctrl-X deletes and Ctrl-T switches between issues and pull requests.
var reservedKeys = []tui.EventType{tui.Enter, tui.Esc, tui.CtrlC, tui.CtrlG, tui.CtrlX, tui.CtrlT}

// loadCommandConfig reads the user's command configuration. A missing file configures no commands.
func loadCommandConfig() (commandConfig, error) {
	var cfg commandConfig
	path := ""
	if dir := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(dir) {
		path = filepath.Join(dir, "wt", "config.json")
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			path, err = filepath.Abs(filepath.Join(home, ".config", "wt", "config.json"))
		}
		if err != nil {
			return cfg, fmt.Errorf("cannot locate wt config: %w", err)
		}
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, nil
	}
	if err == nil {
		err = parseCommandConfig(data, &cfg)
	}
	if err != nil {
		return commandConfig{}, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

func parseCommandConfig(data []byte, cfg *commandConfig) error {
	if start := bytes.TrimLeft(data, " \t\r\n"); len(start) == 0 || start[0] != '{' {
		return errors.New("expected one JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(cfg); err != nil {
		return err
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return errors.New("expected one JSON object")
	}
	if strings.TrimSpace(cfg.DefaultCommand) == "" {
		cfg.DefaultCommand = ""
	}
	if strings.ContainsRune(cfg.DefaultCommand, 0) {
		return errors.New("default_command must not contain NUL")
	}
	named := map[tui.Event]string{}
	for _, key := range slices.Sorted(maps.Keys(cfg.Keymaps)) {
		event, ok := launchKey(key)
		if !ok {
			return fmt.Errorf("invalid keymap key %q", key)
		}
		if slices.Contains(reservedKeys, event.Type) {
			return fmt.Errorf("keymap key %q is reserved", key)
		}
		if other, ok := named[event]; ok {
			return fmt.Errorf("keymap keys %q and %q name the same key", other, key)
		}
		named[event] = key
		if command := cfg.Keymaps[key]; strings.TrimSpace(command) == "" || strings.ContainsRune(command, 0) {
			return fmt.Errorf("keymaps[%q] must be a non-empty command without NUL", key)
		}
	}
	return nil
}

// launchKey is the key that key names, as fzf's --expect reads it: a single key, spelled as given, that
// the user presses rather than a mouse or synthetic event.
func launchKey(key string) (tui.Event, bool) {
	opts, err := fzf.ParseOptions(false, []string{"--expect=" + key})
	if err != nil || len(opts.Expect) != 1 {
		return tui.Event{}, false
	}
	for event, spelling := range opts.Expect {
		if spelling == key && event.Type < tui.Mouse && !strings.ContainsFunc(spelling, unicode.IsControl) {
			return event, true
		}
	}
	return tui.Event{}, false
}
