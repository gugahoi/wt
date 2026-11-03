package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/cli/go-gh/v2/pkg/auth"
	"github.com/cli/go-gh/v2/pkg/markdown"
	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/cli/go-gh/v2/pkg/term"
	"github.com/cli/go-gh/v2/pkg/text"
)

// GitHub is slow (seconds per call), so `wt issue` and `wt pr` keep a per-repo cache in the state dir:
//
//	issues                     open issues, one "number<TAB>updatedAt<TAB>title<TAB>labels" per line
//	prs                        open pull requests, one "number<TAB>updatedAt<TAB>isDraft<TAB>isCrossRepository
//	                           <TAB>branch<TAB>title<TAB>author<TAB>labels<TAB>review<TAB>reReview" per line
//	previews/<n>-<updatedAt>   the rendered issue or PR, replaced once it changes
//	                           (issues and PRs share one number sequence)

// gitHub connects to the repository the current directory belongs to, as gh does: GH_REPO or the git remotes
// pick it, and the token comes from GH_TOKEN or GITHUB_TOKEN, or else gh's login.
func gitHub() (*api.GraphQLClient, repository.Repository, error) {
	const login = "set GH_TOKEN or run gh auth login"
	repo, err := repository.Current()
	if err != nil {
		if len(auth.KnownHosts()) == 0 {
			return nil, repo, errors.New("not logged in to GitHub: " + login)
		}
		return nil, repo, err
	}
	client, err := api.NewGraphQLClient(api.ClientOptions{Host: repo.Host})
	if err != nil {
		return nil, repo, fmt.Errorf("%w: %s", err, login)
	}
	return client, repo, nil
}

type actor struct {
	Login    string
	Typename string `json:"__typename"` // when queried
}

// login is the actor's login as gh shows it: apps are app/<name>, and deleted accounts ghost.
func (a *actor) login() string {
	if a == nil {
		return "ghost"
	}
	if a.Typename == "Bot" {
		return "app/" + a.Login
	}
	return a.Login
}

type labels struct{ Nodes []struct{ Name string } }

func (l labels) join(sep string) string {
	names := make([]string, len(l.Nodes))
	for i, label := range l.Nodes {
		names[i] = label.Name
	}
	return strings.Join(names, sep)
}

type issue struct {
	Number               int
	CreatedAt, UpdatedAt string
	Title                string
	Labels               labels
}

type review struct {
	Author            *actor
	AuthorAssociation string
	State             string
}

type pullRequest struct {
	Number                     int
	CreatedAt, UpdatedAt       string
	IsDraft, IsCrossRepository bool
	HeadRefName, Title         string
	Author                     *actor
	Labels                     labels
	Reviews                    struct{ Nodes []review }
	ReviewRequests             struct {
		Nodes []struct{ RequestedReviewer *actor }
	}
}

const (
	issueFields = `number createdAt updatedAt title labels(first: 100) { nodes { name } }`
	prFields    = `number createdAt updatedAt isDraft isCrossRepository headRefName title author { __typename login }
		labels(first: 100) { nodes { name } }
		reviews(first: 100) { nodes { author { login } authorAssociation state } }
		reviewRequests(first: 100) { nodes { requestedReviewer { ... on User { login } ... on Bot { login } ... on Mannequin { login } } } }`
)

// fetchOpen fetches the newest 500 open issues or pull requests (connection) with the given fields.
// ponytail: a PR's reviews past its first 100 go unseen; page through them if that's ever too few.
func fetchOpen[T any](connection, fields string) ([]T, error) {
	client, repo, err := gitHub()
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf(`query($owner: String!, $name: String!, $after: String) {
		repository(owner: $owner, name: $name) {
			items: %s(first: 100, after: $after, states: OPEN, orderBy: {field: CREATED_AT, direction: DESC}) {
				nodes { %s }
				pageInfo { hasNextPage endCursor }
			}
		}
	}`, connection, fields)
	vars := map[string]any{"owner": repo.Owner, "name": repo.Name, "after": nil}
	var items []T
	for len(items) < 500 {
		var page struct {
			Repository struct {
				Items struct {
					Nodes    []T
					PageInfo struct {
						HasNextPage bool
						EndCursor   string
					}
				}
			}
		}
		if err := client.Do(query, vars, &page); err != nil {
			return nil, err
		}
		items = append(items, page.Repository.Items.Nodes...)
		if !page.Repository.Items.PageInfo.HasNextPage {
			break
		}
		vars["after"] = page.Repository.Items.PageInfo.EndCursor
	}
	return items[:min(len(items), 500)], nil
}

// newestFirst sorts items by creation, newest first.
func newestFirst[T any](items []T, created func(T) string) {
	slices.SortStableFunc(items, func(a, b T) int { return strings.Compare(created(a), created(b)) })
	slices.Reverse(items)
}

func issueCacheLines(issues []issue) []string {
	newestFirst(issues, func(i issue) string { return i.CreatedAt })
	out := make([]string, len(issues))
	for i, is := range issues {
		out[i] = fmt.Sprintf("%d\t%s\t%s\t%s", is.Number, is.UpdatedAt, is.Title, is.Labels.join(","))
	}
	return out
}

// prCacheLines lists pull requests ready for review newest first, then drafts newest first. PRs from forks
// are checked out into a local pr-<number> branch, since their head branch doesn't exist on origin.
func prCacheLines(prs []pullRequest) []string {
	newestFirst(prs, func(pr pullRequest) string { return pr.CreatedAt })
	slices.SortStableFunc(prs, func(a, b pullRequest) int { return boolInt(a.IsDraft) - boolInt(b.IsDraft) })
	out := make([]string, len(prs))
	for i, pr := range prs {
		branch := pr.HeadRefName
		if pr.IsCrossRepository {
			branch = fmt.Sprintf("pr-%d", pr.Number)
		}
		status, reReview := reviewStatus(pr)
		out[i] = fmt.Sprintf("%d\t%s\t%t\t%t\t%s\t%s\t%s\t%s\t%s\t%t", pr.Number, pr.UpdatedAt, pr.IsDraft,
			pr.IsCrossRepository, branch, pr.Title, pr.Author.login(), pr.Labels.join(","), status, reReview)
	}
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// reviewStatus is changes, approved, commented or none, from each reviewer's latest approval or change
// request, and whether a reviewer was asked to review again. Only reviewers with write access count, so
// bots don't. GitHub's latestReviews leaves out re-requested reviewers, hence all the reviews.
func reviewStatus(pr pullRequest) (string, bool) {
	author := pr.Author.login()
	verdicts := map[string]string{}
	reviewed := map[string]bool{}
	for _, r := range pr.Reviews.Nodes {
		switch who := r.Author.login(); {
		case r.State == "PENDING", who == author:
		case r.AuthorAssociation != "OWNER" && r.AuthorAssociation != "MEMBER" && r.AuthorAssociation != "COLLABORATOR":
		default:
			reviewed[who] = true
			if r.State != "COMMENTED" {
				verdicts[who] = r.State
			}
		}
	}
	reReview := false
	for _, request := range pr.ReviewRequests.Nodes {
		// teams have no login
		reReview = reReview || request.RequestedReviewer != nil && reviewed[request.RequestedReviewer.Login]
	}
	changes, approved := false, false
	for _, state := range verdicts {
		changes = changes || state == "CHANGES_REQUESTED"
		approved = approved || state == "APPROVED"
	}
	switch {
	case changes:
		return "changes", reReview
	case approved:
		return "approved", reReview
	case len(reviewed) > 0:
		return "commented", reReview
	}
	return "none", reReview
}

// writeCache replaces the cache file whole, so readers never see half of it.
func writeCache(name string, cacheLines []string) error {
	file, err := stateDir(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d", file, os.Getpid())
	data := strings.Join(cacheLines, "\n")
	if data != "" {
		data += "\n"
	}
	if err := os.WriteFile(tmp, []byte(data), 0o644); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, file)
}

// readCache returns the cache's lines, split into fields, skipping lines that don't start with a number.
func readCache(name string) [][]string {
	file, err := stateDir(name)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var rows [][]string
	for _, line := range lines(string(data)) {
		f := strings.Split(line, "\t")
		if !isNumber(f[0]) {
			continue
		}
		for len(f) < 10 {
			f = append(f, "")
		}
		rows = append(rows, f)
	}
	return rows
}

func isNumber(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// refresh fetches the issues or PRs from GitHub into the cache, at most once per picker: kinds already
// fetched are marked in the $WT_REFRESHED directory, so switching back and forth doesn't refetch.
func refresh(kind string) error {
	marker := ""
	if dir := os.Getenv("WT_REFRESHED"); dir != "" {
		marker = filepath.Join(dir, kind)
		if _, err := os.Stat(marker); err == nil {
			return nil
		}
	}
	if _, err := stateDir(kind + "s"); err != nil {
		return err
	}
	var err error
	switch kind {
	case "issue":
		var issues []issue
		if issues, err = fetchOpen[issue]("issues", issueFields); err == nil {
			err = writeCache("issues", issueCacheLines(issues))
		}
	case "pr":
		var prs []pullRequest
		if prs, err = fetchOpen[pullRequest]("pullRequests", prFields); err == nil {
			err = writeCache("prs", prCacheLines(prs))
		}
	default:
		return fmt.Errorf("unknown kind %q", kind)
	}
	if err == nil && marker != "" {
		os.WriteFile(marker, nil, 0o644)
	}
	return err
}

// issueLines lists the cached issues for fzf as "issue<TAB>number<TAB>updatedAt<TAB>display<TAB>tags",
// tagging those with a <number>-* branch [wt] or [br]. Displays are padded to 300 columns, so they always
// overflow the list and --freeze-right keeps the tags showing at the edge, cutting the title instead.
// Even unmarked issues need a non-whitespace tag: fzf strips trailing whitespace before freezing fields,
// which otherwise freezes the entire title and clips its beginning on long rows.
func issueLines() []string {
	rows := readCache("issues")
	if rows == nil {
		return nil
	}
	mark := map[string]string{}
	for _, line := range listBranches() {
		name, _, _ := strings.Cut(line, "\t")
		number, _, ok := strings.Cut(name, "-")
		if _, err := strconv.ParseUint(number, 10, 64); !ok || err != nil {
			continue
		}
		if strings.HasSuffix(name, " [wt]") {
			mark[number] = "[wt]"
		} else if _, ok := mark[number]; !ok {
			mark[number] = "[br]"
		}
	}
	out := make([]string, len(rows))
	for i, f := range rows {
		display := "#" + f[0] + "  " + f[2]
		if f[3] != "" {
			display += "  \033[2m[" + f[3] + "]\033[0m"
		}
		tag := mark[f[0]]
		if tag == "" {
			tag = "\033[2m·\033[0m"
		}
		out[i] = fmt.Sprintf("issue\t%s\t%s\t%-300s\t  %s", f[0], f[1], display, tag)
	}
	return out
}

// prLines lists the cached PRs for fzf as "pr<TAB>number<TAB>updatedAt<TAB>display<TAB>tags", tagging those
// whose branch has a worktree [wt] or exists locally [br], and each one's review status, last.
func prLines() []string {
	rows := readCache("prs")
	if rows == nil {
		return nil
	}
	mark := map[string]string{}
	for branch := range localBranches() {
		mark[branch] = "[br] "
	}
	for branch := range worktreeBranches() {
		mark[branch] = "[wt] "
	}
	reviews := map[string]string{
		"approved":  "\033[32m[approved]\033[0m",
		"changes":   "\033[31m[changes requested]\033[0m",
		"commented": "\033[36m[commented]\033[0m",
		"none":      "\033[2m[unreviewed]\033[0m",
	}
	out := make([]string, len(rows))
	for i, f := range rows {
		display := "#" + f[0] + "  " + f[5] + "  \033[2m@" + f[6]
		if f[7] != "" {
			display += " [" + f[7] + "]"
		}
		tags := mark[f[4]]
		if f[2] == "true" {
			tags += "\033[33m[draft]\033[0m "
		}
		if f[9] == "true" {
			tags += "\033[35m[re-review]\033[0m "
		}
		out[i] = fmt.Sprintf("pr\t%s\t%s\t%-300s\t  %s", f[0], f[1], display+"\033[0m", tags+reviews[f[8]])
	}
	return out
}

// pickerKind is what the picker is showing (issue or pr), read from fzf's prompt.
func pickerKind() string {
	if strings.HasPrefix(os.Getenv("FZF_PROMPT"), "PR") {
		return "pr"
	}
	return "issue"
}

func pickerHeader(kind string) string {
	if kind == "pr" {
		return "Ctrl-T: switch to issues"
	}
	return "Ctrl-T: switch to pull requests"
}

// cmdLines lists the cached issues or PRs for fzf: [--refresh] [kind], kind being the one the picker shows
// by default. --refresh fetches them from GitHub first.
func cmdLines(args []string) []string {
	refreshing := len(args) > 0 && args[0] == "--refresh"
	if refreshing {
		args = args[1:]
	}
	kind := pickerKind()
	if len(args) > 0 && args[0] != "" {
		kind = args[0]
	}
	if refreshing {
		refresh(kind)
	}
	switch kind {
	case "issue":
		return issueLines()
	case "pr":
		return prLines()
	}
	return nil
}

// toggleActions are the fzf actions switching the picker between issues and PRs. load is rebound so the
// switched-to list, shown from the cache straight away, gets refreshed from GitHub.
func toggleActions() string {
	kind, prompt := "issue", "Issue> "
	if pickerKind() == "issue" {
		kind, prompt = "pr", "PR> "
	}
	return fmt.Sprintf("change-prompt(%s)+change-header(%s)+rebind(load)+reload-sync(%s --lines %s)",
		prompt, pickerHeader(kind), shellQuote(self()), kind)
}

// cmdGitHub lists the repo's open GitHub issues or PRs, Ctrl-T switching between them, and opens the picked
// one with the command the key pressed picks. The cached list shows straight away and is swapped for a fresh
// one once GitHub answers (load is unbound first so the reload doesn't retrigger it); only a first run waits
// on GitHub.
func cmdGitHub(kind string) error {
	if _, err := muxSetting(); err != nil {
		return err
	}
	cfg, err := loadCommandConfig()
	if err != nil {
		return err
	}
	prompt := "Issue> "
	if kind == "pr" {
		prompt = "PR> "
	}
	refreshed, err := os.MkdirTemp("", "wt.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(refreshed)
	// fzf's commands run in child processes
	os.Setenv("WT_REFRESHED", refreshed)
	if readCache(kind+"s") == nil {
		if err := refresh(kind); err != nil {
			return err
		}
	}
	wt := shellQuote(self())
	picked, command, err := pickLaunch(cmdLines([]string{kind}), cfg, cfg.DefaultCommand, false, "--ansi",
		"--prompt="+prompt, "--header="+pickerHeader(kind),
		"--delimiter=\t", "--with-nth=4..", "--freeze-right=1", "--no-wrap", "--no-keep-right", "--ellipsis=",
		"--bind=load:unbind(load)+reload-sync("+wt+" --lines --refresh)",
		"--bind=ctrl-t:transform("+wt+" --toggle)",
		"--preview="+wt+" --preview {1} {2} {3}", "--preview-window=right,50%,wrap")
	if err != nil || picked == "" {
		return err
	}
	f := strings.Split(picked, "\t")
	if len(f) < 2 {
		return nil
	}
	switch f[0] {
	case "issue":
		return openIssue(f[1], cfg, command)
	case "pr":
		return openPR(f[1], command)
	}
	return nil
}

// cmdIssue opens open issue n, with the default command, as picking it in `wt issue` would.
func cmdIssue(n string) error {
	cfg, err := numbered("issue", n)
	if err != nil {
		return err
	}
	return openIssue(n, cfg, cfg.DefaultCommand)
}

// cmdPR opens open pull request n, with the default command, as picking it in `wt pr` would.
func cmdPR(n string) error {
	cfg, err := numbered("pr", n)
	if err != nil {
		return err
	}
	return openPR(n, cfg.DefaultCommand)
}

// numbered checks that n is the number of an open issue or PR (kind), and loads the command config. The
// issues or PRs are fetched from GitHub first when n isn't in the cache, so one opened since the last fetch
// is found.
func numbered(kind, n string) (commandConfig, error) {
	noun, article := "issue", "an"
	if kind == "pr" {
		noun, article = "pull request", "a"
	}
	if !isNumber(n) {
		return commandConfig{}, fmt.Errorf("'%s' is not %s %s number", n, article, noun)
	}
	if _, err := muxSetting(); err != nil {
		return commandConfig{}, err
	}
	cfg, err := loadCommandConfig()
	if err != nil {
		return commandConfig{}, err
	}
	cached := func() bool {
		return slices.ContainsFunc(readCache(kind+"s"), func(f []string) bool { return f[0] == n })
	}
	if !cached() {
		if err := refresh(kind); err != nil {
			return commandConfig{}, err
		}
		if !cached() {
			return commandConfig{}, fmt.Errorf("no open %s #%s", noun, n)
		}
	}
	return cfg, nil
}

// openIssue offers the issue's existing <number>-* branches or a new one named in an editable prompt, and
// switches to it with command, unless a key pressed in either picker picks another.
func openIssue(n string, cfg commandConfig, command string) error {
	const newBranch = "+ new branch"
	branch := newBranch
	var matches []string
	for _, line := range listBranches() {
		if strings.HasPrefix(line, n+"-") {
			matches = append(matches, line)
		}
	}
	if len(matches) > 0 {
		picked, pickedCommand, err := pickLaunch(append([]string{newBranch}, matches...), cfg, command, false, "--ansi",
			"--no-sort", "--delimiter=\t", "--with-nth=1,2", "--prompt=#"+n+"> ")
		if err != nil || picked == "" {
			return err
		}
		branch, command = picked, pickedCommand
	}
	if branch == newBranch {
		title := ""
		for _, f := range readCache("issues") {
			if f[0] == n {
				title = f[2]
				break
			}
		}
		named, namedCommand, err := pickLaunch(nil, cfg, command, true, "--prompt=New branch> ", "--info=hidden",
			"--query="+n+"-"+slug(title))
		if err != nil || named == "" {
			return err
		}
		if branch, command = named, namedCommand; !strings.HasPrefix(branch, n+"-") {
			branch = n + "-" + branch
		}
	}
	return switchToBranch(branch, command)
}

// slug turns an issue title into a branch name: its first five lowercase words, joined with dashes.
func slug(title string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(title) {
		if 'a' <= r && r <= 'z' || '0' <= r && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	words := strings.Split(strings.TrimPrefix(b.String(), "-"), "-")
	return strings.TrimSuffix(strings.Join(words[:min(len(words), 5)], "-"), "-")
}

// openPR switches to the PR's branch, with command, fetching it from GitHub when there's no local branch yet.
func openPR(n, command string) error {
	var cross, branch string
	for _, f := range readCache("prs") {
		if f[0] == n {
			cross, branch = f[3], f[4]
			break
		}
	}
	if branch == "" {
		return nil
	}
	if err := muxPreflight(); err != nil {
		return err
	}
	if !gitOK("show-ref", "--verify", "--quiet", "refs/heads/"+branch) {
		var out strings.Builder
		var err error
		if cross == "true" {
			err = gitTo(&out, &out, "fetch", "--quiet", "origin", "+refs/pull/"+n+"/head:refs/heads/"+branch)
		} else if err = gitTo(&out, &out, "fetch", "--quiet", "origin", "+refs/heads/"+branch+":refs/remotes/origin/"+branch); err == nil {
			err = gitTo(&out, &out, "branch", "--quiet", "--track", branch, "origin/"+branch)
		}
		if err != nil {
			msg := strings.TrimRight(out.String(), "\n")
			if msg == "" {
				msg = "unknown error"
			}
			wtError("failed to fetch PR #" + n + ": " + msg)
			return errReported
		}
	}
	return switchToBranch(branch, command)
}

// preview prints an issue or PR the way `gh issue view` / `gh pr view` show it, cached until its updatedAt
// changes. Renders cut short by fzf killing the preview leave a .<n>.<pid> file, cleared next time.
func preview(kind, n, updated string) error {
	if kind != "issue" && kind != "pr" {
		return errReported
	}
	dir, err := stateDir("previews")
	if err != nil {
		return err
	}
	file := filepath.Join(dir, n+"-"+updated)
	if info, err := os.Stat(file); err != nil || info.Size() == 0 {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		removeGlob(filepath.Join(dir, "."+n+".*"))
		rendered, err := render(kind, n)
		if err != nil {
			fmt.Println(err)
			return errReported
		}
		tmp := filepath.Join(dir, fmt.Sprintf(".%s.%d", n, os.Getpid()))
		if err := os.WriteFile(tmp, []byte(rendered), 0o644); err != nil {
			return err
		}
		removeGlob(filepath.Join(dir, n+"-*"))
		if err := os.Rename(tmp, file); err != nil {
			return err
		}
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

func removeGlob(pattern string) {
	files, _ := filepath.Glob(pattern)
	for _, f := range files {
		os.Remove(f)
	}
}

// details is an issue or pull request as its preview shows it.
type details struct {
	Title, URL, State, Body string
	Number                  int
	IsDraft                 bool
	CreatedAt               time.Time
	Author                  *actor
	Comments, Commits       struct{ TotalCount int }
	BaseRefName             string
	HeadRefName             string
	Additions, Deletions    int
	Assignees               struct{ Nodes []actor }
	Labels                  labels
	Milestone               *struct{ Title string }
	ReviewRequests          struct {
		Nodes []struct {
			RequestedReviewer *struct{ Login, CombinedSlug string }
		}
	}
	LatestReviews struct {
		Nodes []struct {
			Author *actor
			State  string
		}
	}
}

const (
	detailFields = `title url state body number createdAt author { __typename login } comments { totalCount }
		assignees(first: 100) { nodes { login } } labels(first: 100) { nodes { name } } milestone { title }`
	prDetailFields = `isDraft commits { totalCount } baseRefName headRefName additions deletions
		reviewRequests(first: 100) { nodes { requestedReviewer {
			... on User { login } ... on Bot { login } ... on Mannequin { login } ... on Team { combinedSlug } } } }
		latestReviews(first: 100) { nodes { author { login } state } }`
)

// render shows an issue or PR, for the picker's preview, much as gh's view commands do.
func render(kind, n string) (string, error) {
	number, err := strconv.Atoi(n)
	if err != nil {
		return "", err
	}
	client, repo, err := gitHub()
	if err != nil {
		return "", err
	}
	field, fields := "issue", detailFields
	if kind == "pr" {
		field, fields = "pullRequest", detailFields+" "+prDetailFields
	}
	query := fmt.Sprintf(`query($owner: String!, $name: String!, $number: Int!) {
		repository(owner: $owner, name: $name) { item: %s(number: $number) { %s } }
	}`, field, fields)
	var resp struct{ Repository struct{ Item details } }
	if err := client.Do(query, map[string]any{"owner": repo.Owner, "name": repo.Name, "number": number}, &resp); err != nil {
		return "", err
	}
	d := resp.Repository.Item

	noColor := term.IsColorDisabled()
	style := func(code, s string) string {
		if noColor {
			return s
		}
		return "\033[" + code + "m" + s + "\033[0m"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s/%s#%d\n", style("1", d.Title), repo.Owner, repo.Name, d.Number)
	ago := text.RelativeTimeAgo(time.Now(), d.CreatedAt)
	if kind == "issue" {
		state := style("32", "Open")
		if d.State == "CLOSED" {
			state = style("35", "Closed")
		}
		fmt.Fprintf(&b, "%s • %s opened %s • %s\n", state, d.Author.login(), ago, text.Pluralize(d.Comments.TotalCount, "comment"))
	} else {
		state := map[string]string{"OPEN": style("32", "Open"), "CLOSED": style("31", "Closed"), "MERGED": style("35", "Merged")}[d.State]
		if d.IsDraft && d.State == "OPEN" {
			state = style("90", "Draft")
		}
		fmt.Fprintf(&b, "%s • %s wants to merge %s into %s from %s • %s\n", state, d.Author.login(),
			text.Pluralize(d.Commits.TotalCount, "commit"), d.BaseRefName, d.HeadRefName, ago)
		fmt.Fprintf(&b, "%s %s • %s\n", style("32", "+"+strconv.Itoa(d.Additions)), style("31", "-"+strconv.Itoa(d.Deletions)),
			text.Pluralize(d.Comments.TotalCount, "comment"))
	}
	var reviewers []string
	for _, r := range d.LatestReviews.Nodes {
		verdict := map[string]string{"APPROVED": style("32", "Approved"), "CHANGES_REQUESTED": style("31", "Requested changes"),
			"COMMENTED": "Commented", "DISMISSED": "Dismissed"}[r.State]
		if verdict != "" {
			reviewers = append(reviewers, r.Author.login()+" ("+verdict+")")
		}
	}
	for _, r := range d.ReviewRequests.Nodes {
		if r.RequestedReviewer != nil {
			reviewers = append(reviewers, r.RequestedReviewer.Login+r.RequestedReviewer.CombinedSlug+" (Requested)")
		}
	}
	var assignees []string
	for _, a := range d.Assignees.Nodes {
		assignees = append(assignees, a.Login)
	}
	for _, meta := range []struct{ name, value string }{
		{"Reviewers", strings.Join(reviewers, ", ")},
		{"Assignees", strings.Join(assignees, ", ")},
		{"Labels", d.Labels.join(", ")},
		{"Milestone", func() string {
			if d.Milestone == nil {
				return ""
			}
			return d.Milestone.Title
		}()},
	} {
		if meta.value != "" {
			fmt.Fprintf(&b, "%s %s\n", style("1", meta.name+":"), meta.value)
		}
	}

	body := "\n  " + style("90", "No description provided") + "\n\n"
	if d.Body != "" {
		width, err := strconv.Atoi(os.Getenv("FZF_PREVIEW_COLUMNS"))
		if err != nil {
			width = 80
		}
		// The preview isn't a terminal, so gh would fall back to its dark theme too.
		theme := "dark"
		if noColor {
			theme = "none"
		}
		if body, err = markdown.Render(d.Body, markdown.WithTheme(theme), markdown.WithWrap(width)); err != nil {
			return "", err
		}
	}
	fmt.Fprintf(&b, "\n%s\n", body)
	what := "issue"
	if kind == "pr" {
		what = "pull request"
	}
	fmt.Fprintln(&b, style("90", fmt.Sprintf("View this %s on GitHub: %s", what, d.URL)))
	return b.String(), nil
}
