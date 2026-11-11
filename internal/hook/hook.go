// Package hook implements the soft protection layer: a Claude Code
// PreToolUse hook that turns tool calls into allow/ask/deny decisions.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/ASromancer/agentssh/internal/paths"
	"github.com/ASromancer/agentssh/internal/policy"
)

// Explainer asks the daemon what it would do with cmd on host
// ("run", "ask", "approve" or "block").
type Explainer func(host, cmd, cwd string) (action string, err error)

type event struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
	Cwd       string         `json:"cwd"`
}

type output struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// Claude reads one PreToolUse event and writes a decision. No output means
// "no opinion": Claude Code's normal permission flow applies.
func Claude(in io.Reader, out io.Writer, protected []string, explain Explainer) error {
	var ev event
	if err := json.NewDecoder(in).Decode(&ev); err != nil {
		return err
	}
	decision, reason := Decide(ev.ToolName, ev.ToolInput, ev.Cwd, protected, explain)
	if decision == "" {
		return nil
	}
	var o output
	o.HookSpecificOutput.HookEventName = "PreToolUse"
	o.HookSpecificOutput.PermissionDecision = decision
	o.HookSpecificOutput.PermissionDecisionReason = reason
	return json.NewEncoder(out).Encode(o)
}

var (
	directSSH  = map[string]bool{"ssh": true, "scp": true, "sftp": true, "mosh": true, "slogin": true}
	humanOnly  = map[string]bool{"approve": true, "key": true, "reload": true, "host": true, "init": true, "install-hooks": true, "unlock": true}
	readOnlyUs = map[string]bool{"hosts": true, "out": true, "explain": true, "help": true, "version": true}
)

func Decide(tool string, input map[string]any, cwd string, protected []string, explain Explainer) (string, string) {
	switch tool {
	case "Edit", "Write", "MultiEdit", "NotebookEdit":
		p, _ := input["file_path"].(string)
		if p == "" {
			p, _ = input["notebook_path"].(string)
		}
		if p != "" && inside(p, cwd, protected) {
			return "deny", "agentssh config and state can only be changed by the user"
		}
		return "", ""
	case "Bash":
		cmd, _ := input["command"].(string)
		return bash(cmd, cwd, protected, explain)
	}
	return "", ""
}

func inside(p, cwd string, dirs []string) bool {
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	cands := []string{filepath.Clean(p)}
	if r, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		cands = append(cands, filepath.Join(r, filepath.Base(p)))
	}
	for _, c := range cands {
		for _, d := range dirs {
			if paths.Within(c, d) {
				return true
			}
		}
	}
	return false
}

// remoteArg spots rsync remote syntax: host:path, user@host:path, rsync://.
func remoteArg(a string) bool {
	if strings.HasPrefix(a, "rsync://") {
		return true
	}
	if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "/") || strings.HasPrefix(a, ".") {
		return false
	}
	if len(a) >= 2 && a[1] == ':' && (a[0]|0x20 >= 'a' && a[0]|0x20 <= 'z') { // C:\ or C:/ on Windows
		return false
	}
	i := strings.Index(a, ":")
	return i > 0 && !strings.Contains(a[:i], "/")
}

// runArgs extracts host and command from "agentssh run|job start <host> <cmd> [flags]".
func runArgs(args []string) (host, cmd string, ok bool) {
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--timeout" || a == "-timeout" || a == "--lines":
			i++
		case strings.HasPrefix(a, "-") && len(pos) < 2:
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) < 2 {
		return "", "", false
	}
	return pos[0], pos[1], true
}

func bash(cmd, cwd string, protected []string, explain Explainer) (string, string) {
	calls, writes, err := policy.Calls(cmd)
	if err != nil {
		return "", ""
	}
	ours := len(calls) > 0 && !writes
	var ask string
	for _, argv := range calls {
		// Git Bash on Windows: SSH.exe, agentssh.exe
		name := strings.TrimSuffix(strings.ToLower(argv[0]), ".exe")
		switch {
		case directSSH[name]:
			return "deny", fmt.Sprintf("do not call %s directly; use 'agentssh run <host> \"<cmd>\"' (see 'agentssh hosts')", name)
		case name == "rsync":
			for _, a := range argv[1:] {
				if remoteArg(a) {
					return "deny", "do not rsync to remote hosts directly; use 'agentssh put/get'"
				}
			}
			ours = false
		case name == "agentssh":
			sub := ""
			if len(argv) > 1 {
				sub = argv[1]
			}
			rest := argv[min(2, len(argv)):]
			switch {
			case humanOnly[sub]:
				return "deny", fmt.Sprintf("'agentssh %s' is for the human user only; ask the user to run it", sub)
			case sub == "run" || (sub == "job" && len(rest) > 0 && rest[0] == "start"):
				if sub == "job" {
					rest = rest[1:]
				}
				host, rcmd, ok := runArgs(rest)
				if !ok || host == "$?" || rcmd == "$?" {
					ask = "agentssh command is built dynamically; please confirm"
					continue
				}
				action, err := explain(host, rcmd, cwd)
				if err != nil {
					ask = "agentssh daemon is not responding: " + err.Error()
					continue
				}
				switch action {
				case "block":
					return "deny", fmt.Sprintf("agentssh policy blocks this on %s; run 'agentssh explain' for details and ask the user", host)
				case "ask":
					ask = fmt.Sprintf("command changes state on %s: %s", host, rcmd)
				}
			case sub == "job" || readOnlyUs[sub]:
			default:
				ours = false
			}
		default:
			ours = false
		}
	}
	if ask == "" && mentions(cmd, protected) {
		ask = "command touches agentssh config/state"
	}
	switch {
	case ask != "":
		return "ask", ask
	case ours:
		return "allow", "agentssh policy allows this"
	}
	return "", ""
}

func mentions(cmd string, dirs []string) bool {
	norm := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, `\`, "/")) }
	c := norm(cmd)
	for _, d := range append([]string{".config/agentssh", ".local/state/agentssh", "appdata/roaming/agentssh",
		"appdata/local/agentssh", "$appdata/agentssh", "$localappdata/agentssh"}, dirs...) {
		if strings.Contains(c, norm(d)) {
			return true
		}
	}
	return false
}
