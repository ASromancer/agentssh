package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ASromancer/agentssh/internal/daemon"
	"github.com/ASromancer/agentssh/internal/hook"
	"github.com/ASromancer/agentssh/internal/paths"
	"github.com/ASromancer/agentssh/internal/policy"
)

// The text helpers below are shared by the CLI and the MCP server so agents
// see the same output either way.

func hostsText(hs []daemon.HostInfo) string {
	if len(hs) == 0 {
		return "no hosts available to agents here (the user enables them with 'agentssh host edit <name> --agent')\n"
	}
	var b strings.Builder
	for _, h := range hs {
		fmt.Fprintf(&b, "%s\t%s\t%s\n", h.Name, h.Profile, h.Description)
	}
	return b.String()
}

func runText(host string, r daemon.ExecReply) string {
	return fmt.Sprintf("%s exit=%d %.1fs level=%s id=%d\n%s", host, r.Exit, float64(r.DurMs)/1000, r.Level, r.ID, r.Output)
}

func transferText(host, kind string, r daemon.ExecReply) string {
	return fmt.Sprintf("%s %s ok %.1fs level=%s id=%d\n", host, kind, float64(r.DurMs)/1000, r.Level, r.ID)
}

func jobStartText(host string, r daemon.ExecReply) string {
	return fmt.Sprintf("%s job started level=%s id=%d (agentssh job tail %d)\n", host, r.Level, r.ID, r.ID)
}

func jobTailText(id int, r daemon.JobReply) string {
	state := "running"
	if !r.Running {
		state = fmt.Sprintf("exit=%d", r.Exit)
	}
	return fmt.Sprintf("job %d %s\n%s", id, state, r.Output)
}

func explainText(r daemon.ExplainReply) string {
	var b strings.Builder
	fmt.Fprintf(&b, "level=%s\n", r.Level)
	for _, x := range r.Reasons {
		fmt.Fprintf(&b, "  %-11s %s\n", x.Level, x.Text)
	}
	if r.HostOK {
		fmt.Fprintf(&b, "host=%s profile=%s action=%s\n", r.Host, r.Profile, r.Action)
	}
	if r.Msg != "" {
		b.WriteString(r.Msg + "\n")
	}
	return b.String()
}

// readOutput returns a stored output, optionally limited to a line range
// "a:b" (1-based, inclusive) and filtered by a regexp (with line numbers).
func readOutput(id int, grep, rng string) (string, error) {
	b, err := os.ReadFile(daemon.OutPath(id))
	if err != nil {
		return "", fmt.Errorf("no output for id %d (outputs are kept 7 days)", id)
	}
	lines := strings.SplitAfter(string(b), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	from, to := 1, len(lines)
	if rng != "" {
		a, z, ok := strings.Cut(rng, ":")
		if !ok {
			return "", errors.New("range must look like a:b")
		}
		if a != "" {
			from, _ = strconv.Atoi(a)
		}
		if z != "" {
			to, _ = strconv.Atoi(z)
		}
		from, to = max(from, 1), min(to, len(lines))
	}
	var re *regexp.Regexp
	if grep != "" {
		if re, err = regexp.Compile(grep); err != nil {
			return "", fmt.Errorf("bad grep: %v", err)
		}
	}
	var out strings.Builder
	for i := from; i <= to; i++ {
		l := strings.TrimSuffix(lines[i-1], "\n")
		if re == nil {
			out.WriteString(l + "\n")
		} else if re.MatchString(l) {
			fmt.Fprintf(&out, "%d: %s\n", i, l)
		}
	}
	return out.String(), nil
}

// explainCmd classifies a command, through the daemon when it runs (host
// rules apply) or locally with default + user rules otherwise.
func explainCmd(e daemon.Env, cmd, host string) (daemon.ExplainReply, error) {
	var r daemon.ExplainReply
	if c, _ := daemon.Dial(); c != nil {
		defer c.Close()
		err := c.Call("A.Explain", &daemon.ExplainArgs{Env: e, Cmd: cmd, Host: host}, &r)
		return r, err
	}
	eng, err := policy.Load(paths.Rules())
	if err != nil {
		return r, err
	}
	r.Result = eng.Classify(cmd, nil, nil)
	if host != "" {
		r.Msg = "daemon not running; host rules not applied"
	}
	return r, nil
}

func cmdHosts(args []string) int {
	fs := newFlags("hosts")
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return 2
	}
	c, code := dial()
	if c == nil {
		return code
	}
	defer c.Close()
	var r daemon.HostsReply
	e := env()
	if err := c.Call("A.Hosts", &e, &r); err != nil {
		return callErr(err)
	}
	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(r.Hosts)
		return 0
	}
	fmt.Print(hostsText(r.Hosts))
	return 0
}

// execute runs an Exec request, waiting for human approval when needed.
func execute(a daemon.ExecArgs) (daemon.ExecReply, int) {
	c, code := dial()
	if c == nil {
		return daemon.ExecReply{}, code
	}
	defer c.Close()
	a.Env = env()
	for {
		var r daemon.ExecReply
		if err := c.Call("A.Exec", &a, &r); err != nil {
			return r, callErr(err)
		}
		if r.Pending == 0 {
			if r.Code != 0 {
				return r, agentFail(r.Code, r.Msg)
			}
			return r, -1
		}
		fmt.Fprintf(os.Stderr, "agentssh: waiting approval #%d — run 'agentssh approve' in another terminal\n", r.Pending)
		a.ApprovalID = r.Pending
	}
}

// finish prints a transport error and returns the remote exit code.
func finish(r daemon.ExecReply) int {
	if r.Msg != "" {
		fmt.Fprintf(os.Stderr, "agentssh: %s\n", r.Msg)
	}
	return r.Exit
}

func cmdRun(args []string) int {
	fs := newFlags("run")
	timeout := fs.Duration("timeout", daemon.DefaultTimeout, "kill the command after this long")
	asJSON := fs.Bool("json", false, "JSON output")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 2 {
		return errf(2, `usage: agentssh run <host> "<cmd>" (quote the command as one argument)`)
	}
	r, code := execute(daemon.ExecArgs{Kind: "run", Host: pos[0], Cmd: pos[1], Timeout: *timeout})
	if code >= 0 {
		return code
	}
	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"host": pos[0], "exit": r.Exit, "duration_ms": r.DurMs,
			"level": r.Level, "id": r.ID, "output": r.Output, "error": r.Msg})
		return r.Exit
	}
	fmt.Print(runText(pos[0], r))
	return finish(r)
}

func cmdOut(args []string) int {
	fs := newFlags("out")
	grep := fs.String("grep", "", "only lines matching this regexp (with line numbers)")
	rng := fs.String("range", "", "line range a:b (1-based, inclusive; either side may be empty)")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 1 {
		return errf(2, "usage: agentssh out <id> [--grep <regexp>] [--range a:b]")
	}
	id, err := strconv.Atoi(pos[0])
	if err != nil {
		return errf(2, "bad id %q", pos[0])
	}
	out, err := readOutput(id, *grep, *rng)
	if err != nil {
		return errf(1, "%v", err)
	}
	fmt.Print(out)
	return 0
}

func splitRemote(s string) (host, path string, ok bool) {
	host, path, ok = strings.Cut(s, ":")
	return host, path, ok && host != "" && path != ""
}

func transfer(kind string, args []string) int {
	pos, err := parse(newFlags(kind), args)
	if err != nil {
		return 2
	}
	if len(pos) != 2 {
		return errf(2, "usage: agentssh get <host>:<remote> <local> | agentssh put <local> <host>:<remote>")
	}
	remoteArg, local := pos[0], pos[1]
	if kind == "put" {
		remoteArg, local = pos[1], pos[0]
	}
	host, remote, ok := splitRemote(remoteArg)
	if !ok {
		return errf(2, "expected <host>:<remote-path>, got %q", remoteArg)
	}
	abs, err := filepath.Abs(local)
	if err != nil {
		return errf(2, "%v", err)
	}
	r, code := execute(daemon.ExecArgs{Kind: kind, Host: host, Remote: remote, Local: abs})
	if code >= 0 {
		return code
	}
	if r.Exit == 0 {
		fmt.Print(transferText(host, kind, r))
	}
	return finish(r)
}

func cmdGet(args []string) int { return transfer("get", args) }
func cmdPut(args []string) int { return transfer("put", args) }

func cmdJob(args []string) int {
	if len(args) == 0 {
		return errf(2, "usage: agentssh job start|tail|kill ...")
	}
	sub := args[0]
	fs := newFlags("job " + sub)
	lines := fs.Int("lines", 20, "lines to show")
	pos, err := parse(fs, args[1:])
	if err != nil {
		return 2
	}
	switch sub {
	case "start":
		if len(pos) != 2 {
			return errf(2, `usage: agentssh job start <host> "<cmd>"`)
		}
		r, code := execute(daemon.ExecArgs{Kind: "job", Host: pos[0], Cmd: pos[1]})
		if code >= 0 {
			return code
		}
		if r.Msg != "" {
			return finish(r)
		}
		fmt.Print(jobStartText(pos[0], r))
		return 0
	case "tail", "kill":
		if len(pos) != 1 {
			return errf(2, "usage: agentssh job %s <id>", sub)
		}
		id, err := strconv.Atoi(pos[0])
		if err != nil {
			return errf(2, "bad id %q", pos[0])
		}
		c, code := dial()
		if c == nil {
			return code
		}
		defer c.Close()
		var r daemon.JobReply
		method := map[string]string{"tail": "A.JobTail", "kill": "A.JobKill"}[sub]
		if err := c.Call(method, &daemon.JobArgs{ID: id, Lines: *lines}, &r); err != nil {
			return callErr(err)
		}
		if sub == "kill" {
			fmt.Printf("job %d killed\n", id)
			return 0
		}
		fmt.Print(jobTailText(id, r))
		return 0
	}
	return errf(2, "unknown job subcommand %q", sub)
}

func cmdExplain(args []string) int {
	fs := newFlags("explain")
	host := fs.String("host", "", "also show what the host's profile would do")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 1 {
		return errf(2, `usage: agentssh explain "<cmd>" [--host <host>]`)
	}
	r, err := explainCmd(env(), pos[0], *host)
	if err != nil {
		return callErr(err)
	}
	fmt.Print(explainText(r))
	return 0
}

// daemonExplain asks the daemon for the action on host, with a short timeout
// so a hung daemon never blocks the agent.
func daemonExplain(host, cmd, cwd string) (string, error) {
	c, err := daemon.Dial()
	if err != nil {
		return "", err
	}
	defer c.Close()
	var r daemon.ExplainReply
	call := c.Go("A.Explain", &daemon.ExplainArgs{Env: daemon.Env{Cwd: cwd}, Cmd: cmd, Host: host}, &r, nil)
	select {
	case <-call.Done:
		return r.Action, call.Error
	case <-time.After(3 * time.Second):
		return "", fmt.Errorf("timeout")
	}
}

func cmdHook(args []string) int {
	if len(args) != 1 || args[0] != "claude" {
		return errf(2, "usage: agentssh hook claude (reads a PreToolUse event on stdin)")
	}
	if err := hook.Claude(os.Stdin, os.Stdout, []string{paths.Config(), paths.State()}, daemonExplain); err != nil {
		// Never break the agent on a malformed event: no output = normal flow.
		fmt.Fprintf(os.Stderr, "agentssh hook: %v\n", err)
	}
	return 0
}
