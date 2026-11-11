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
	if err := Claude(bytes.NewReader(in), &out, append([]string{filepath.Join(home, ".config", "ostiary"), filepath.Join(home, ".local", "state", "ostiary")}, ServicePaths(home)...), fakeExplain); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		return ""
	}
	var o claudeOut
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
		{`ostiary run web1 "ls -la"`, "allow"},
		{`ostiary run web1 "df -h" --timeout 30s`, "allow"},
		{`ostiary run web1 "rm -rf /tmp/x"`, "allow"}, // daemon asks for approval itself
		{`ostiary run web1 "systemctl restart nginx"`, "ask"},
		{`ostiary run web1 "cat ~/.ssh/id_rsa"`, "deny"},
		{`ostiary run down "ls"`, "ask"},
		{`ostiary run web1 "$CMD"`, "ask"},
		{`ostiary job start web1 "tail -f /var/log/syslog"`, "allow"},
		{`ostiary hosts`, "allow"},
		{`ostiary out 12 --grep error`, "allow"},
		{`ostiary approve`, "deny"},
		{`ostiary key export web1`, "deny"},
		{`ostiary reload`, "deny"},
		{`ostiary install-service`, "deny"},
		{`cd /tmp && ostiary approve`, "deny"},
		{`ssh web1 uptime`, "deny"},
		{`/usr/bin/ssh web1`, "deny"},
		{`sudo scp a web1:/tmp`, "deny"},
		{`bash -c 'ssh web1 ls'`, "deny"},
		{`rsync -av ./dist/ deploy@web1:/srv/app`, "deny"},
		{`rsync -av ./a ./b`, ""},
		{`ostiary run web1 "ls" && rm -rf ~`, ""}, // local command: normal permission flow
		{`ostiary run web1 "ls" > ~/.bashrc`, ""},
		{`ostiary run web1 "ls" | head`, ""},
		{`ls -la`, ""},
		{`cat ~/.config/ostiary/hosts.toml`, "ask"},
		{`git status`, ""},
		{`SSH.exe web1`, "deny"},
		{`rsync -av C:/src/ D:/backup/`, ""},
		{`cat $APPDATA/ostiary/hosts.toml`, "ask"},
		// Restarting the daemon could switch it to codes: human only.
		{`ostiary ui`, "deny"},
		{`ostiary open`, "deny"},
		{`ostiary upgrade`, "deny"},
		{`ostiary uninstall-service`, "deny"},
		{`ostiary daemon --detach`, "deny"},
		{`OSTIARY_OS_AUTH=0 ostiary daemon`, "deny"},
		{`systemctl --user restart ostiary.service`, "deny"},
		{`systemctl --user set-environment OSTIARY_OS_AUTH=0`, "deny"},
		{`$env:ostiary_os_auth = "0"`, "deny"},
		{`systemctl --user restart ostiary`, "deny"},
		{`pkill ostiary`, "deny"},
		{`pkill -f "ostiary daemon"`, "deny"},
		{`killall ostiary`, "deny"},
		{`kill 1234`, ""},
		{`/usr/bin/pkill ostiary`, "deny"},
		{`kill -9 $(pgrep ostiary)`, "deny"},
		{`kill $(pidof Ostiary)`, "deny"},
		{`launchctl kickstart -k gui/501/dev.ostiary`, "deny"},
		// Changing how user services start: human only, ostiary named or not.
		{`systemctl --user set-environment LD_PRELOAD=/tmp/x.so`, "deny"},
		{`systemctl --user unset-environment DISPLAY`, "deny"},
		{`systemctl --user import-environment`, "deny"},
		{`systemctl --user daemon-reload`, "deny"},
		{`systemctl --user edit foo`, "deny"},
		{`systemctl --user revert foo`, "deny"},
		{`launchctl setenv DYLD_INSERT_LIBRARIES /tmp/x`, "deny"},
		{`launchctl unsetenv PATH`, "deny"},
		{`launchctl kickstart -k gui/501/com.example`, "deny"},
		{`launchctl bootout gui/501/com.example`, "deny"},
		{`launchctl unload ~/Library/LaunchAgents/x.plist`, "deny"},
		{`launchctl load ~/Library/LaunchAgents/x.plist`, "deny"},
		{`systemctl status nginx`, ""},
		{`systemctl --user status pipewire`, ""},
		{`launchctl list`, ""},
		{`echo X=1 >> ~/.config/environment.d/x.conf`, "ask"},
	} {
		if got := run(t, "Bash", map[string]any{"command": tc.cmd}); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.cmd, got, tc.want)
		}
	}
}

func TestEditWrite(t *testing.T) {
	// Writing a document that merely mentions ostiary's paths is fine;
	// writing INTO them is not.
	doc := map[string]any{"file_path": filepath.Join(home, "work", "notes.md"),
		"content": "state lives in " + filepath.Join(home, ".config", "ostiary")}
	if got := run(t, "Write", doc); got != "" {
		t.Errorf("write mentioning ostiary paths: %q", got)
	}
	if got := run(t, "Write", map[string]any{"file_path": filepath.Join(home, ".config", "ostiary", "hosts.toml")}); got != "deny" {
		t.Errorf("write config: %q", got)
	}
	if got := run(t, "Edit", map[string]any{"file_path": filepath.Join(home, ".local", "state", "ostiary", "audit.jsonl")}); got != "deny" {
		t.Errorf("edit audit: %q", got)
	}
	for _, p := range []string{
		filepath.Join(home, ".config", "systemd", "user", "ostiary.service.d", "override.conf"),
		filepath.Join(home, ".config", "environment.d", "50-x.conf"),
	} {
		if got := run(t, "Write", map[string]any{"file_path": p}); got != "deny" {
			t.Errorf("write %s: %q", p, got)
		}
	}
	if got := run(t, "Edit", map[string]any{"file_path": filepath.Join(home, "work", "main.go")}); got != "" {
		t.Errorf("normal edit: %q", got)
	}
}

func runAgent(t *testing.T, agent string, event map[string]any) map[string]any {
	t.Helper()
	in, _ := json.Marshal(event)
	var out bytes.Buffer
	if err := Run(agent, bytes.NewReader(in), &out, []string{filepath.Join(home, ".config", "ostiary")}, fakeExplain); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		return nil
	}
	var o map[string]any
	if err := json.Unmarshal(out.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestCodex(t *testing.T) {
	ev := func(cmd string) map[string]any {
		return map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": home, "tool_input": map[string]any{"command": cmd}}
	}
	if o := runAgent(t, "codex", ev("ssh web1 uptime")); o == nil || o["hookSpecificOutput"].(map[string]any)["permissionDecision"] != "deny" {
		t.Errorf("codex ssh: %v", o)
	}
	// ask and allow are not reliable in Codex: no output, the daemon enforces.
	for _, c := range []string{`ostiary run web1 "systemctl restart nginx"`, `ostiary run web1 "ls"`} {
		if o := runAgent(t, "codex", ev(c)); o != nil {
			t.Errorf("codex %s: %v", c, o)
		}
	}
	patch := map[string]any{"tool_name": "apply_patch", "cwd": home, "tool_input": map[string]any{
		"input": "*** Begin Patch\n*** Update File: " + filepath.Join(home, ".config", "ostiary", "hosts.toml") + "\n"}}
	if o := runAgent(t, "codex", patch); o == nil {
		t.Error("codex apply_patch on ostiary config was not denied")
	}
}

func TestGemini(t *testing.T) {
	ev := func(cmd string) map[string]any {
		return map[string]any{"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "cwd": home,
			"tool_input": map[string]any{"command": cmd, "description": "x"}}
	}
	for cmd, want := range map[string]any{
		"scp a web1:/tmp":                            "deny",
		`ostiary run web1 "df -h"`:                   "allow",
		`ostiary run web1 "systemctl restart nginx"`: nil,
		"ls": nil,
	} {
		o := runAgent(t, "gemini", ev(cmd))
		if (o == nil) != (want == nil) || (o != nil && o["decision"] != want) {
			t.Errorf("gemini %s: %v", cmd, o)
		}
	}
	w := map[string]any{"tool_name": "write_file", "cwd": home, "tool_input": map[string]any{"file_path": filepath.Join(home, ".config", "ostiary", "rules.toml")}}
	if o := runAgent(t, "gemini", w); o == nil || o["decision"] != "deny" {
		t.Errorf("gemini write_file: %v", o)
	}
}

func TestAntigravity(t *testing.T) {
	ev := func(cmd string) map[string]any {
		return map[string]any{"toolCall": map[string]any{"name": "run_command", "args": map[string]any{"CommandLine": cmd, "Cwd": home}},
			"workspacePaths": []any{home}, "conversationId": "c"}
	}
	if o := runAgent(t, "antigravity", ev("ssh -p 22 root@web1")); o == nil || o["decision"] != "deny" {
		t.Errorf("antigravity ssh: %v", o)
	}
	if o := runAgent(t, "antigravity", ev(`ostiary run web1 "uptime"`)); o == nil || o["decision"] != "allow" {
		t.Errorf("antigravity ostiary: %v", o)
	}
	if o := runAgent(t, "antigravity", ev("ostiary key export web1")); o == nil || o["decision"] != "deny" {
		t.Errorf("antigravity admin: %v", o)
	}
}
