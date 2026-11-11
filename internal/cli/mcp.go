package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ASromancer/ostiary/internal/daemon"
)

// MCP: a stdio server (newline-delimited JSON-RPC 2.0) exposing the agent
// commands as tools, for clients that have no shell or no hooks. It is a
// thin layer over the same daemon RPC; policy and approvals are unchanged.

var mcpVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// approvalPoll bounds one tool call while waiting for a human, below the
// ~60 s tool timeout of common MCP clients.
const approvalPoll = 45 * time.Second

const mcpInstructions = `ostiary runs shell commands on remote servers for you without exposing SSH keys.
Start with the hosts tool. Every command is classified read/mutate/destructive/forbidden.
Destructive commands need the human to approve in a terminal ('ostiary approve'); the run tool then
returns an approval id: call run again with the same host, command and approval_id until it finishes.
If a result says the request was denied or blocked, stop and ask the user; never retry another way.
No PTY: use 'top -bn1', 'cat', 'tail -n' instead of interactive programs. Prefer the output tool with
grep over re-running heavy commands.`

type rpcCaller interface {
	Call(method string, args, reply any) error
	Close() error
}

type mcpServer struct {
	dial func() (rpcCaller, error)
	env  daemon.Env
	mu   sync.Mutex
	out  io.Writer
}

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func cmdMCP(args []string) int {
	fs := newFlags("mcp")
	cwd := fs.String("cwd", "", "directory used to find .ostiary.toml (default: current directory)")
	if _, err := parse(fs, args); err != nil {
		return 2
	}
	e := env()
	if *cwd != "" {
		abs, err := filepath.Abs(*cwd)
		if err != nil {
			return errf(2, "%v", err)
		}
		e.Cwd = abs
	}
	e.Agent = "mcp" // no soft ask over MCP: mutate on standard hosts needs approval
	s := &mcpServer{env: e, out: os.Stdout, dial: func() (rpcCaller, error) { return daemon.Dial() }}
	if err := s.serve(os.Stdin); err != nil {
		return errf(1, "%v", err)
	}
	return 0
}

func (s *mcpServer) serve(in io.Reader) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	var wg sync.WaitGroup
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var m rpcMsg
		if err := json.Unmarshal(line, &m); err != nil {
			s.send(rpcMsg{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			continue
		}
		if m.Method == "" || len(m.ID) == 0 {
			continue // responses and notifications need no answer
		}
		wg.Add(1)
		go func() { // tool calls may wait for approval; keep reading meanwhile
			defer wg.Done()
			res, err := s.handle(m.Method, m.Params)
			reply := rpcMsg{JSONRPC: "2.0", ID: m.ID, Result: res, Error: err}
			if err == nil && res == nil {
				reply.Result = struct{}{}
			}
			s.send(reply)
		}()
	}
	wg.Wait()
	return sc.Err()
}

func (s *mcpServer) send(m rpcMsg) {
	b, _ := json.Marshal(m)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out.Write(append(b, '\n'))
}

func (s *mcpServer) handle(method string, params json.RawMessage) (any, *rpcError) {
	switch method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(params, &p)
		v := mcpVersions[0]
		if slices.Contains(mcpVersions, p.ProtocolVersion) {
			v = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "ostiary", "version": Version},
			"instructions":    mcpInstructions,
		}, nil
	case "ping":
		return struct{}{}, nil
	case "tools/list":
		return map[string]any{"tools": mcpTools}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		text, isErr := s.call(p.Name, p.Arguments)
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "isError": isErr}, nil
	}
	return nil, &rpcError{-32601, "method not found: " + method}
}

func obj(props map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": append([]string{}, required...)}
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func num(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }

func tool(name, title, desc string, schema map[string]any, readOnly, destructive bool) map[string]any {
	return map[string]any{"name": name, "title": title, "description": desc, "inputSchema": schema,
		"annotations": map[string]any{"readOnlyHint": readOnly, "destructiveHint": destructive, "openWorldHint": true}}
}

var mcpTools = []any{
	tool("hosts", "List hosts", "Hosts you may use, with their profile (readonly|standard|full) and description.",
		obj(map[string]any{}), true, false),
	tool("run", "Run a command", "Run one shell command on a host. Output keeps the first and last 40 lines; use the output tool for the rest. "+
		"If approval is needed the result says so: call run again with the same host, command and approval_id.",
		obj(map[string]any{
			"host":            str("host name from the hosts tool"),
			"command":         str("shell command, run by the remote user's shell"),
			"timeout_seconds": num("kill the command after this many seconds (default 60)"),
			"approval_id":     num("id from a previous 'approval required' result"),
		}, "host", "command"), false, true),
	tool("output", "Read stored output", "Full output of an earlier run or job, optionally filtered.",
		obj(map[string]any{
			"id":    num("id from a run/job result"),
			"grep":  str("only lines matching this regexp, with line numbers"),
			"range": str("line range a:b, 1-based inclusive, either side may be empty"),
		}, "id"), true, false),
	tool("explain", "Classify a command", "How ostiary classifies a command and what it would do on a host. Runs nothing.",
		obj(map[string]any{"command": str("shell command"), "host": str("optional host to apply its profile and rules")}, "command"), true, false),
	tool("get", "Download a file", "Copy a remote file (max 50 MB) to a local absolute path.",
		obj(map[string]any{"host": str("host"), "remote_path": str("remote file"), "local_path": str("local absolute path"),
			"approval_id": num("id from a previous 'approval required' result")}, "host", "remote_path", "local_path"), false, false),
	tool("put", "Upload a file", "Copy a local file (max 50 MB) to the host.",
		obj(map[string]any{"host": str("host"), "local_path": str("local absolute path"), "remote_path": str("remote file"),
			"approval_id": num("id from a previous 'approval required' result")}, "host", "local_path", "remote_path"), false, true),
	tool("job_start", "Start a background job", "Start a long-running command; read it with job_tail.",
		obj(map[string]any{"host": str("host"), "command": str("shell command"),
			"approval_id": num("id from a previous 'approval required' result")}, "host", "command"), false, true),
	tool("job_tail", "Tail a job", "Status and last lines of a background job.",
		obj(map[string]any{"id": num("job id"), "lines": num("lines to show (default 20)")}, "id"), true, false),
	tool("job_kill", "Kill a job", "Stop a background job.", obj(map[string]any{"id": num("job id")}, "id"), false, false),
}

func argStr(a map[string]any, k string) string { s, _ := a[k].(string); return s }
func argInt(a map[string]any, k string) int    { f, _ := a[k].(float64); return int(f) }

func failText(code int, msg string) string {
	return fmt.Sprintf("ostiary: %s\nostiary: %s (code %d)", msg, guidance[code], code)
}

// call runs one tool and returns its text and whether it is an error.
func (s *mcpServer) call(name string, a map[string]any) (string, bool) {
	if name == "output" {
		out, err := daemon.ReadOutput(argInt(a, "id"), argStr(a, "grep"), argStr(a, "range"))
		if err != nil {
			return err.Error(), true
		}
		return out, false
	}
	if name == "explain" {
		r, err := explainCmd(s.env, argStr(a, "command"), argStr(a, "host"))
		if err != nil {
			return err.Error(), true
		}
		return explainText(r), false
	}
	c, err := s.dial()
	if err != nil {
		return failText(daemon.CodeNoDaemon, "daemon is not running"), true
	}
	defer c.Close()
	call := func(method string, args, reply any) error {
		err := c.Call(method, args, reply)
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return errors.New(failText(daemon.CodeNoDaemon, "lost connection to the daemon"))
		}
		return err
	}
	switch name {
	case "hosts":
		var r daemon.HostsReply
		if err := call("A.Hosts", &s.env, &r); err != nil {
			return err.Error(), true
		}
		return hostsText(r.Hosts), false
	case "job_tail", "job_kill":
		var r daemon.JobReply
		id := argInt(a, "id")
		method := map[string]string{"job_tail": "A.JobTail", "job_kill": "A.JobKill"}[name]
		if err := call(method, &daemon.JobArgs{ID: id, Lines: argInt(a, "lines")}, &r); err != nil {
			return err.Error(), true
		}
		if name == "job_kill" {
			return fmt.Sprintf("job %d killed\n", id), false
		}
		return jobTailText(id, r), false
	}

	x := daemon.ExecArgs{Env: s.env, Host: argStr(a, "host"), ApprovalID: argInt(a, "approval_id"), WaitMax: approvalPoll}
	switch name {
	case "run":
		x.Kind, x.Cmd = "run", argStr(a, "command")
		x.Timeout = time.Duration(argInt(a, "timeout_seconds")) * time.Second
	case "job_start":
		x.Kind, x.Cmd = "job", argStr(a, "command")
	case "get", "put":
		x.Kind, x.Remote, x.Local = name, argStr(a, "remote_path"), argStr(a, "local_path")
		if x.Local != "" && !filepath.IsAbs(x.Local) {
			x.Local = filepath.Join(s.env.Cwd, x.Local)
		}
	default:
		return "unknown tool " + name, true
	}
	if x.Host == "" {
		return "host is required", true
	}
	var r daemon.ExecReply
	if err := call("A.Exec", &x, &r); err != nil {
		return err.Error(), true
	}
	switch {
	case r.Pending != 0 && x.ApprovalID == 0:
		return fmt.Sprintf("approval required (#%d): this is %s. The user must run 'ostiary approve' in a terminal and "+
			"enter the code from the desktop notification. Tell the user, then call %s again with the same arguments "+
			"and approval_id=%d.", r.Pending, r.Level, name, r.Pending), false
	case r.Pending != 0:
		return fmt.Sprintf("still waiting for the user to approve #%d. Call %s again with approval_id=%d.",
			r.Pending, name, r.Pending), false
	case r.Code != 0:
		return failText(r.Code, r.Msg), true
	}
	var text string
	switch x.Kind {
	case "run":
		text = runText(x.Host, r)
	case "job":
		text = jobStartText(x.Host, r)
	default:
		if r.Exit == 0 {
			text = transferText(x.Host, x.Kind, r)
		}
	}
	if r.Msg != "" {
		text += "ostiary: " + r.Msg + "\n"
	}
	return text, r.Exit != 0 && x.Kind != "run"
}
