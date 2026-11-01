package main

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	fzf "github.com/junegunn/fzf/src"
)

// pick shows input in fzf, run with args, and returns what fzf printed along with its exit code:
// fzf.ExitOk, fzf.ExitNoMatch, or fzf.ExitInterrupt when the user cancelled. Tests replace it.
var pick = runFzf

func runFzf(input []string, args ...string) ([]string, int) {
	// fzf would open a tmux or Zellij popup (--popup/--tmux in FZF_DEFAULT_OPTS) by running the program's own
	// command line again, which is wt's rather than fzf's when fzf is a library: keep it in this terminal.
	opts, err := fzf.ParseOptions(true, append(args, "--no-popup"))
	if err != nil {
		wtError("fzf: " + err.Error())
		return nil, fzf.ExitError
	}
	opts.Input = make(chan string, len(input))
	for _, line := range input {
		opts.Input <- line
	}
	close(opts.Input)

	opts.Output = make(chan string)
	var out []string
	collected := make(chan struct{})
	go func() {
		for line := range opts.Output {
			out = append(out, line)
		}
		close(collected)
	}()
	code, err := fzf.Run(opts)
	close(opts.Output)
	<-collected
	if err != nil {
		wtError("fzf: " + err.Error())
	}
	return out, code
}

// pickLaunch shows a picker for a worktree to open, and returns the row picked along with the command to
// open it with: command for Enter (or a mouse accept), or the one cfg maps the key pressed instead to.
// allowQuery lets a query that matches nothing be picked, naming a new branch. The keys are fzf --expect
// keys rather than bindings, so commands never become part of fzf's action syntax.
func pickLaunch(input []string, cfg commandConfig, command string, allowQuery bool, args ...string) (string, string, error) {
	keys := slices.Sorted(maps.Keys(cfg.Keymaps))
	args = append(slices.Clip(args), "--no-multi", "--print-query", "--no-expect", "--expect=enter")
	for _, key := range keys {
		args = append(args, "--expect="+key)
	}
	if command != "" || len(keys) > 0 {
		var footer strings.Builder
		footer.WriteString("Enter: ")
		if command == "" {
			footer.WriteString("shell")
		} else {
			footer.WriteString(strconv.Quote(command))
		}
		for _, key := range keys {
			fmt.Fprintf(&footer, "   %s: %s", key, strconv.Quote(cfg.Keymaps[key]))
		}
		args = append(args, "--footer="+footer.String())
	}
	out, code := pick(input, args...)
	switch code {
	case fzf.ExitInterrupt:
		return "", "", nil
	case fzf.ExitOk, fzf.ExitNoMatch:
	default:
		return "", "", errReported
	}
	// fzf prints the query, the key pressed, then the row picked (none when nothing matches the query).
	if len(out) == 0 {
		return "", "", nil
	}
	if len(out) < 2 {
		return "", "", errors.New("invalid launch picker output")
	}
	if key := out[1]; key != "" && key != "enter" {
		mapped, ok := cfg.Keymaps[key]
		if !ok {
			return "", "", fmt.Errorf("unexpected picker key %q", key)
		}
		command = mapped
	}
	picked := ""
	if len(out) > 2 {
		picked = out[2]
	}
	if picked == "" && allowQuery {
		picked = out[0]
	}
	if picked == "" {
		return "", "", nil
	}
	return picked, command, nil
}
