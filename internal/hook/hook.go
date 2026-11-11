// Package hook implements the soft protection layer: pre-tool hooks for
// Claude Code, Codex, Gemini CLI and Antigravity that turn tool calls into
// allow/ask/deny decisions. Policy, approvals and forbidden commands are
// enforced by the daemon regardless; this layer catches direct ssh, keeps
// agents away from ostiary's own files and admin commands, and lets Claude
// Code ask before state-changing commands.
package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ASromancer/ostiary/internal/paths"
	"github.com/ASromancer/ostiary/internal/policy"
)

// Explainer asks the daemon what it would do with cmd on host
// ("run", "ask", "approve" or "block").
type Explainer func(host, cmd, cwd string) (action string, err error)

// Agents with a hook format.
var Agents = []string{"claude", "codex", "gemini", "antigravity"}

// Run reads one pre-tool event in agent's format from in and writes the
// decision to out. No output means "no opinion": the agent's normal
// permission flow applies.
func Run(agent string, in io.Reader, out io.Writer, protected []string, explain Explainer) error {
	var raw map[string]any
	if err := json.NewDecoder(in).Decode(&raw); err != nil {
		return err
	}
	tool, _ := raw["tool_name"].(string)
	input, _ := raw["tool_input"].(map[string]any)
	cwd, _ := raw["cwd"].(string)
	if agent == "antigravity" {
		tc, _ := raw["toolCall"].(map[string]any)
		tool, _ = tc["name"].(string)
		input, _ = tc["args"].(map[string]any)
		cwd, _ = input["Cwd"].(string)
		if ws, _ := raw["workspacePaths"].([]any); cwd == "" && len(ws) > 0 {
			cwd, _ = ws[0].(string)
		}
	}
	decision, reason := Decide(tool, input, cwd, protected, explain)

	var o any
	switch agent {
	case "claude":
		if decision != "" {
			o = claudeOutput(decision, reason)
		}
	case "codex":
		// Codex runs the command anyway on "ask", and plain "allow" is not a
		// documented output: only deny. The daemon turns state-changing
		// commands from Codex into out-of-band approvals instead.
		if decision == "deny" {
			o = claudeOutput(decision, reason)
		}
	case "gemini", "antigravity":
		if decision == "deny" || decision == "allow" {
			o = map[string]string{"decision": decision, "reason": reason}
		}
	default:
		return errors.New("unknown agent " + agent)
	}
	if o == nil {
		return nil
	}
	return json.NewEncoder(out).Encode(o)
}

type claudeOut struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

func claudeOutput(decision, reason string) claudeOut {
	var o claudeOut
	o.HookSpecificOutput.HookEventName = "PreToolUse"
	o.HookSpecificOutput.PermissionDecision = decision
	o.HookSpecificOutput.PermissionDecisionReason = reason
	return o
}

// Claude is Run for Claude Code.
func Claude(in io.Reader, out io.Writer, protected []string, explain Explainer) error {
	return Run("claude", in, out, protected, explain)
}

var (
	directSSH  = map[string]bool{"ssh": true, "scp": true, "sftp": true, "mosh": true, "slogin": true}
	humanOnly  = map[string]bool{"approve": true, "key": true, "reload": true, "host": true, "init": true, "install-hooks": true, "unlock": true, "daemon": true, "install-service": true, "ui": true, "open": true, "stop": true, "upgrade": true, "uninstall-service": true}
	readOnlyUs = map[string]bool{"hosts": true, "out": true, "explain": true, "help": true, "version": true}
	// A restarted daemon picks its auth mode again, so stopping it is human only.
	stopTools = map[string]bool{"systemctl": true, "pkill": true, "kill": true, "killall": true, "launchctl": true}
	// Verbs that change the environment or definition user services start
	// with (systemctl only with --user).
	serviceVerbs = map[string]map[string]bool{
		"systemctl": {"set-environment": true, "unset-environment": true, "import-environment": true, "daemon-reload": true, "edit": true, "revert": true},
		"launchctl": {"setenv": true, "unsetenv": true, "kickstart": true, "bootout": true, "unload": true, "load": true},
	}
)

// changesServices reports whether argv changes how user services start.
func changesServices(name string, args []string) bool {
	if name == "systemctl" && !slices.Contains(args, "--user") {
		return false
	}
	return slices.ContainsFunc(args, func(a string) bool { return serviceVerbs[name][a] })
}

// Shell tools of each agent: Claude/Codex Bash, Codex shell/exec_command,
// Gemini run_shell_command, Antigravity run_command.
var shellTools = map[string]bool{"Bash": true, "shell": true, "exec_command": true, "run_shell_command": true, "run_command": true}

// shellCommand extracts the command line from a shell tool's input.
func shellCommand(input map[string]any) string {
	for _, k := range []string{"command", "CommandLine", "cmd"} {
		switch v := input[k].(type) {
		case string:
			return v
		case []any: // ["bash", "-lc", "<script>"]
			parts := make([]string, 0, len(v))
			for _, p := range v {
				s, _ := p.(string)
				parts = append(parts, s)
			}
			if len(parts) == 3 && (parts[1] == "-lc" || parts[1] == "-c") {
				return parts[2]
			}
			return strings.Join(parts, " ")
		}
	}
	return ""
}

func Decide(tool string, input map[string]any, cwd string, protected []string, explain Explainer) (string, string) {
	if shellTools[tool] {
		return bash(shellCommand(input), cwd, protected, explain)
	}
	// Any other tool (Edit, Write, apply_patch, write_file, replace, ...):
	// refuse if it targets ostiary's own files.
	hasPath := false
	for _, k := range []string{"file_path", "notebook_path", "path", "TargetFile", "AbsolutePath"} {
		if p, _ := input[k].(string); p != "" {
			hasPath = true
			if inside(p, cwd, protected) {
				return "deny", "ostiary config and state can only be changed by the user"
			}
		}
	}
	if !hasPath && mentions(fmt.Sprint(input), protected) { // fmt, not JSON: no escaped backslashes
		return "deny", "ostiary config and state can only be changed by the user"
	}
	return "", ""
}

// ServicePaths are the files that decide how the ostiary service starts
// (unit, drop-ins, session environment, launch agent); the hook protects
// them like ostiary's own config.
func ServicePaths(home string) []string {
	user := filepath.Join(home, ".config", "systemd", "user")
	return []string{
		filepath.Join(user, "ostiary.service"),
		filepath.Join(user, "ostiary.service.d"),
		filepath.Join(home, ".config", "environment.d"),
		filepath.Join(home, "Library", "LaunchAgents", "dev.ostiary.plist"),
	}
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

// runArgs extracts host and command from "ostiary run|job start <host> <cmd> [flags]".
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
	// Restarting the daemon with another environment can switch it to codes.
	if l := strings.ToLower(cmd); strings.Contains(l, "ostiary_os_auth") || strings.Contains(l, "ostiary.service") {
		return "deny", "changing how ostiary authenticates is for the human user only"
	}
	calls, writes, err := policy.Calls(cmd)
	if err != nil {
		return "", ""
	}
	ours := len(calls) > 0 && !writes
	var ask string
	for _, argv := range calls {
		// Git Bash on Windows: SSH.exe, ostiary.exe
		name := strings.TrimSuffix(strings.ToLower(argv[0]), ".exe")
		switch {
		case directSSH[name]:
			return "deny", fmt.Sprintf("do not call %s directly; use 'ostiary run <host> \"<cmd>\"' (see 'ostiary hosts')", name)
		// Raw text, not argv: catches kill $(pgrep ostiary).
		case stopTools[name] && strings.Contains(strings.ToLower(cmd), "ostiary"):
			return "deny", "stopping or restarting ostiary is for the human user only"
		case changesServices(name, argv[1:]):
			return "deny", "changing how user services start is for the human user only"
		case name == "rsync":
			for _, a := range argv[1:] {
				if remoteArg(a) {
					return "deny", "do not rsync to remote hosts directly; use 'ostiary put/get'"
				}
			}
			ours = false
		case name == "ostiary":
			sub := ""
			if len(argv) > 1 {
				sub = argv[1]
			}
			rest := argv[min(2, len(argv)):]
			switch {
			case humanOnly[sub]:
				return "deny", fmt.Sprintf("'ostiary %s' is for the human user only; ask the user to run it", sub)
			case sub == "run" || (sub == "job" && len(rest) > 0 && rest[0] == "start"):
				if sub == "job" {
					rest = rest[1:]
				}
				host, rcmd, ok := runArgs(rest)
				if !ok || host == "$?" || rcmd == "$?" {
					ask = "ostiary command is built dynamically; please confirm"
					continue
				}
				action, err := explain(host, rcmd, cwd)
				if err != nil {
					ask = "ostiary daemon is not responding: " + err.Error()
					continue
				}
				switch action {
				case "block":
					return "deny", fmt.Sprintf("ostiary policy blocks this on %s; run 'ostiary explain' for details and ask the user", host)
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
		ask = "command touches ostiary config/state"
	}
	switch {
	case ask != "":
		return "ask", ask
	case ours:
		return "allow", "ostiary policy allows this"
	}
	return "", ""
}

func mentions(cmd string, dirs []string) bool {
	norm := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, `\`, "/")) }
	c := norm(cmd)
	for _, d := range append([]string{".config/ostiary", ".local/state/ostiary", "appdata/roaming/ostiary",
		"appdata/local/ostiary", "$appdata/ostiary", "$localappdata/ostiary",
		".config/systemd/user/ostiary.service", ".config/environment.d", "launchagents/dev.ostiary.plist"}, dirs...) {
		if strings.Contains(c, norm(d)) {
			return true
		}
	}
	return false
}
