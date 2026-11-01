package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// listPending lists the branches with a deletion in flight, removing stale markers left behind by
// deletion processes that died.
func listPending() []string {
	dir, err := stateDir("pending")
	if err != nil {
		return nil
	}
	entries, _ := os.ReadDir(dir)
	var branches []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		marker := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(marker)
		if err != nil {
			continue
		}
		if pid := strings.TrimSpace(string(data)); pid != "" && !alive(pid) {
			os.Remove(marker)
			continue
		}
		branches = append(branches, decodeBranch(entry.Name()))
	}
	return branches
}

func alive(pid string) bool {
	n, err := strconv.Atoi(pid)
	return err == nil && syscall.Kill(n, 0) == nil
}

// notifyPickers asks every open branch picker of this repo to refresh its list, dropping registrations
// whose socket no longer exists.
func notifyPickers() {
	dir, err := stateDir("sessions")
	if err != nil {
		return
	}
	entries, _ := os.ReadDir(dir)
	action := "reload-sync(" + shellQuote(self()) + " --list-branches)"
	for _, entry := range entries {
		file := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(file)
		if err != nil || !entry.Type().IsRegular() {
			continue
		}
		sock := strings.TrimSpace(string(data))
		if info, err := os.Stat(sock); err != nil || info.Mode().Type() != os.ModeSocket {
			os.Remove(file)
			continue
		}
		client := http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		}}
		if resp, err := client.Post("http://fzf", "text/plain", strings.NewReader(action)); err == nil {
			resp.Body.Close()
		}
	}
}

// deleteSelected deletes the branch picked with Ctrl-X, given its exact ref. Local deletion never deletes
// a remote; remote-only entries need an explicit confirmation first. It returns the background process
// doing the deletion, if one was started.
func deleteSelected(ref, branch string) (*os.Process, error) {
	branch = strings.TrimSuffix(branch, " [wt]")
	if strings.HasSuffix(branch, pendingSuffix) {
		return nil, nil
	}
	if name, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
		return deleteInBackground(name, "")
	}
	remoteBranch, ok := strings.CutPrefix(ref, "refs/remotes/")
	if !ok {
		return nil, nil
	}
	const confirm = "Delete remote branch"
	choice, code := pick([]string{"Cancel", confirm}, "--height=8", "--no-multi", "--no-sort",
		"--prompt=Remote deletion> ", "--header=Delete '"+remoteBranch+"' from the remote? This affects everyone.")
	if code != 0 || len(choice) == 0 || choice[0] != confirm {
		return nil, nil
	}
	return deleteInBackground(branch, ref)
}

// deleteInBackground starts deleting a branch and its worktree, or a confirmed remote branch, in a detached
// process, so several deletions can run at once. It does nothing if the branch is being deleted already.
func deleteInBackground(branch, remoteRef string) (*os.Process, error) {
	if branch == "" {
		return nil, nil
	}
	dir, err := stateDir("pending")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	marker := filepath.Join(dir, encodeBranch(branch))
	if data, err := os.ReadFile(marker); err == nil {
		if pid := strings.TrimSpace(string(data)); pid == "" || alive(pid) {
			return nil, nil
		}
	}
	errorFile, err := stateDir("delete-error")
	if err != nil {
		return nil, err
	}
	os.Remove(errorFile)
	if err := os.WriteFile(marker, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		return nil, err
	}
	// Its own session keeps the worker out of the picker's process group and away from the terminal.
	worker := exec.Command(self(), "--delete-worker", branch, remoteRef)
	worker.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := worker.Start(); err != nil {
		os.Remove(marker)
		return nil, err
	}
	// The worker removes the marker once it's done, which may already be the case.
	if f, err := os.OpenFile(marker, os.O_WRONLY|os.O_TRUNC, 0); err == nil {
		fmt.Fprintln(f, worker.Process.Pid)
		f.Close()
	}
	return worker.Process, nil
}

// deleteWorker is the background process deleteInBackground starts. It ignores hangups and interrupts so
// it always completes, records why it failed for the picker's header, and refreshes the open pickers.
func deleteWorker(branch, remoteRef string) {
	signal.Ignore(syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	var out bytes.Buffer
	var err error
	if remoteRef != "" {
		err = deleteRemoteBranch(remoteRef, &out)
	} else {
		err = deleteBranchAndWorktree(branch, &out, &out)
	}
	if err != nil {
		if file, e := stateDir("delete-error"); e == nil {
			msg := fmt.Sprintf("Deletion of '%s' failed: %s\n", branch, strings.TrimRight(out.String(), "\n"))
			os.WriteFile(file, []byte(msg), 0o644)
		}
	}
	if dir, e := stateDir("pending"); e == nil {
		os.Remove(filepath.Join(dir, encodeBranch(branch)))
	}
	notifyPickers()
}

// deleteBranchAndWorktree removes the worktree that has branch checked out, if any, then the local branch.
func deleteBranchAndWorktree(branch string, stdout, stderr io.Writer) error {
	branch = strings.TrimSuffix(branch, " [wt]")
	if branch == "" {
		return nil
	}
	if path := worktreeOf(branch); path != "" && !gitOK("worktree", "remove", path) {
		if err := gitTo(stdout, stderr, "worktree", "remove", "--force", path); err != nil {
			return err
		}
	}
	// Allow extra time for packed-refs.lock, held by concurrent deletions
	return gitTo(stdout, stderr, "-c", "core.packedRefsTimeout=5000", "branch", "-D", branch)
}

// deleteRemoteBranch deletes the branch of a remote-tracking ref from its remote. A failed push leaves the
// tracking ref, so rejected or offline deletions stay visible and can be retried.
func deleteRemoteBranch(ref string, out io.Writer) error {
	remote, branch, _ := strings.Cut(strings.TrimPrefix(ref, "refs/remotes/"), "/")
	if err := gitTo(out, out, "push", "--", remote, ":refs/heads/"+branch); err != nil {
		return err
	}
	return gitTo(out, out, "update-ref", "-d", ref)
}

// cmdDelete picks a worktree to remove, along with its branch, after a confirmation read from in.
func cmdDelete(in io.Reader) error {
	list, _ := gitOutput("worktree", "list")
	picked, _ := pick(lines(list), "--height=40%", "--prompt=Select worktree to delete> ")
	if len(picked) == 0 || picked[0] == "" {
		return nil
	}
	fields := strings.Fields(picked[0])
	path, branch := fields[0], ""
	if len(fields) > 2 {
		branch = strings.NewReplacer("[", "", "]", "").Replace(fields[2])
	}
	fmt.Printf("Are you sure you want to delete worktree at: %s and branch %s? (y/N)\n", path, branch)
	response, _ := bufio.NewReader(in).ReadString('\n')
	if response = strings.TrimSpace(response); !strings.EqualFold(response, "y") && !strings.EqualFold(response, "yes") {
		return nil
	}
	if deleteBranchAndWorktree(branch, os.Stdout, errOut) != nil {
		return errReported
	}
	fmt.Println("Worktree and branch removed.")
	return nil
}
