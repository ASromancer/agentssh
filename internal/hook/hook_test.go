package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeExplain(host, cmd, _ string) (string, error) {
	switch {
	case host == "down":
		return "", errors.New("connection refused")
	case strings.HasPrefix(cmd, "rm"):
		return "approve", nil
	case strings.HasPrefix(cmd, "systemctl restart"):
		return "ask", nil
	case strings.Contains(cmd, ".ssh"):
		return "block", nil
	}
	return "run", nil
}

var home = filepath.Join(os.TempDir(), "u")

func run(t *testing.T, tool string, input map[string]any) string {
	t.Helper()
	in, _ := json.Marshal(map[string]any{"tool_name": tool, "tool_input": input, "cwd": home, "hook_event_name": "PreToolUse"})
	var out bytes.Buffer
	if err := Claude(bytes.NewReader(in), &out, []string{filepath.Join(home, ".config", "agentssh"), filepath.Join(home, ".local", "state", "agentssh")}, fakeExplain); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		return ""
	}
	var o output
	if err := json.Unmarshal(out.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	if o.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Fatal("event name")
	}
	return o.HookSpecificOutput.PermissionDecision
}

func TestBash(t *testing.T) {
	for _, tc := range []struct{ cmd, want string }{
		{`agentssh run web1 "ls -la"`, "allow"},
		{`agentssh run web1 "df -h" --timeout 30s`, "allow"},
		{`agentssh run web1 "rm -rf /tmp/x"`, "allow"}, // daemon asks for approval itself
		{`agentssh run web1 "systemctl restart nginx"`, "ask"},
		{`agentssh run web1 "cat ~/.ssh/id_rsa"`, "deny"},
		{`agentssh run down "ls"`, "ask"},
		{`agentssh run web1 "$CMD"`, "ask"},
		{`agentssh job start web1 "tail -f /var/log/syslog"`, "allow"},
		{`agentssh hosts`, "allow"},
		{`agentssh out 12 --grep error`, "allow"},
		{`agentssh approve`, "deny"},
		{`agentssh key export web1`, "deny"},
		{`agentssh reload`, "deny"},
		{`cd /tmp && agentssh approve`, "deny"},
		{`ssh web1 uptime`, "deny"},
		{`/usr/bin/ssh web1`, "deny"},
		{`sudo scp a web1:/tmp`, "deny"},
		{`bash -c 'ssh web1 ls'`, "deny"},
		{`rsync -av ./dist/ deploy@web1:/srv/app`, "deny"},
		{`rsync -av ./a ./b`, ""},
		{`agentssh run web1 "ls" && rm -rf ~`, ""}, // local command: normal permission flow
		{`agentssh run web1 "ls" > ~/.bashrc`, ""},
		{`agentssh run web1 "ls" | head`, ""},
		{`ls -la`, ""},
		{`cat ~/.config/agentssh/hosts.toml`, "ask"},
		{`git status`, ""},
		{`SSH.exe web1`, "deny"},
		{`rsync -av C:/src/ D:/backup/`, ""},
		{`cat $APPDATA/agentssh/hosts.toml`, "ask"},
	} {
		if got := run(t, "Bash", map[string]any{"command": tc.cmd}); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.cmd, got, tc.want)
		}
	}
}

func TestEditWrite(t *testing.T) {
	if got := run(t, "Write", map[string]any{"file_path": filepath.Join(home, ".config", "agentssh", "hosts.toml")}); got != "deny" {
		t.Errorf("write config: %q", got)
	}
	if got := run(t, "Edit", map[string]any{"file_path": filepath.Join(home, ".local", "state", "agentssh", "audit.jsonl")}); got != "deny" {
		t.Errorf("edit audit: %q", got)
	}
	if got := run(t, "Edit", map[string]any{"file_path": filepath.Join(home, "work", "main.go")}); got != "" {
		t.Errorf("normal edit: %q", got)
	}
}
