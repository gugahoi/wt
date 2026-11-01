package main

import (
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
