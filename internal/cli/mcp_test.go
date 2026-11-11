package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ASromancer/agentssh/internal/daemon"
)

// fakeDaemon answers Exec: "pending" once, then runs.
type fakeDaemon struct{ calls []daemon.ExecArgs }

func (f *fakeDaemon) Close() error { return nil }
func (f *fakeDaemon) Call(method string, args, reply any) error {
	switch method {
	case "A.Hosts":
		reply.(*daemon.HostsReply).Hosts = []daemon.HostInfo{{Name: "web1", Profile: "standard", Description: "prod"}}
	case "A.Exec":
		a := *args.(*daemon.ExecArgs)
		f.calls = append(f.calls, a)
		r := reply.(*daemon.ExecReply)
		switch {
		case strings.HasPrefix(a.Cmd, "cat ~/.ssh"):
			r.Code, r.Msg = daemon.CodeBlocked, "blocked: forbidden"
		case strings.HasPrefix(a.Cmd, "rm") && a.ApprovalID == 0:
			r.Pending, r.Level = 7, "destructive"
		default:
			r.ID, r.Level, r.Output = 8, "read", "hi\n"
		}
	}
	return nil
}

func TestMCP(t *testing.T) {
	fd := &fakeDaemon{}
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hosts","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run","arguments":{"host":"web1","command":"echo hi"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run","arguments":{"host":"web1","command":"cat ~/.ssh/id_rsa"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"run","arguments":{"host":"web1","command":"rm x"}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run","arguments":{"host":"web1","command":"rm x","approval_id":7}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"nope"}`,
	}, "\n")
	var out bytes.Buffer
	s := &mcpServer{env: daemon.Env{Agent: "mcp"}, out: &out, dial: func() (rpcCaller, error) { return fd, nil }}
	if err := s.serve(strings.NewReader(in)); err != nil {
		t.Fatal(err)
	}
	res := map[int]map[string]any{}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%v: %s", err, l)
		}
		res[int(m["id"].(float64))] = m
	}
	if len(res) != 8 {
		t.Fatalf("want 8 responses (notification gets none), got %d:\n%s", len(res), out.String())
	}
	text := func(id int) (string, bool) {
		r := res[id]["result"].(map[string]any)
		return r["content"].([]any)[0].(map[string]any)["text"].(string), r["isError"].(bool)
	}
	if v := res[1]["result"].(map[string]any)["protocolVersion"]; v != "2025-06-18" {
		t.Errorf("protocol version %v", v)
	}
	if n := len(res[2]["result"].(map[string]any)["tools"].([]any)); n != 9 {
		t.Errorf("tools: %d", n)
	}
	if s, e := text(3); e || !strings.Contains(s, "web1\tstandard\tprod") {
		t.Errorf("hosts: %q", s)
	}
	if s, e := text(4); e || !strings.Contains(s, "web1 exit=0") || !strings.HasSuffix(s, "hi\n") {
		t.Errorf("run: %q", s)
	}
	if s, e := text(5); !e || !strings.Contains(s, "code 100") {
		t.Errorf("blocked: %q %v", s, e)
	}
	if s, e := text(6); e || !strings.Contains(s, "approval_id=7") {
		t.Errorf("pending: %q", s)
	}
	if s, _ := text(7); !strings.Contains(s, "exit=0") {
		t.Errorf("approved: %q", s)
	}
	if last := fd.calls[len(fd.calls)-1]; last.ApprovalID != 7 || last.WaitMax != approvalPoll || last.Agent != "mcp" {
		t.Errorf("exec args: %+v", last)
	}
	if res[8]["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Errorf("unknown method: %v", res[8])
	}
}
