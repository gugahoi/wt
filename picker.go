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
	opts, err := fzfOptions(args)
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

// fzfOptions parses args over the user's FZF_DEFAULT_OPTS, for a picker shown in this terminal.
func fzfOptions(args []string) (*fzf.Options, error) {
	// fzf would open a tmux or Zellij popup (--popup/--tmux in FZF_DEFAULT_OPTS) by running the program's own
	// command line again, which is wt's rather than fzf's when fzf is a library: keep it in this terminal.
	opts, err := fzf.ParseOptions(true, append(args, "--no-popup"))
	if err != nil {
		return nil, err
	}
	// --filter would make fzf print the matches without showing a picker or the key pressed, and no option
	// undoes it.
	opts.Filter = nil
	return opts, nil
}

// pickLaunch shows a picker for a worktree to open, and returns the row picked along with the command to
// open it with: command for Enter (or a mouse accept), or the one cfg maps the key pressed instead to.
// allowQuery lets a query that matches nothing be picked, naming a new branch. The keys are fzf --expect
// keys rather than bindings, so commands never become part of fzf's action syntax.
func pickLaunch(input []string, cfg commandConfig, command string, allowQuery bool, args ...string) (string, string, error) {
	keys := slices.Sorted(maps.Keys(cfg.Keymaps))
	// Multi-selection and --expect keys in FZF_DEFAULT_OPTS would change what fzf prints, and --exit-0 would
	// skip a picker with nothing to match, like the one naming a new branch, taking its query as the answer.
	args = append(slices.Clip(args), "--no-multi", "--no-exit-0", "--print-query", "--no-expect", "--expect=enter")
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
	// fzf prints the query, the key pressed, whatever print actions in FZF_DEFAULT_OPTS queued, then the row
	// picked, and only then exits ok: when nothing matches the query there's no row, only print output.
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
	if code == fzf.ExitOk && len(out) > 2 {
		picked = out[len(out)-1]
	}
	if picked == "" && allowQuery {
		picked = out[0]
	}
	if picked == "" {
		return "", "", nil
	}
	return picked, command, nil
}
