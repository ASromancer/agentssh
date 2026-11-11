package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ASromancer/agentssh/plugin"
)

// Per-agent integration: skill, pre-tool hook, and a deny rule for direct
// ssh in the agent's own permission system. Formats follow each agent's
// docs as of 2026-11; see README "Agents".

var sshTools = []string{"ssh", "scp", "sftp", "mosh", "slogin"}
var humanOnlySubs = []string{"approve", "key", "reload", "host", "init", "install-hooks", "unlock", "daemon", "install-service"}

type agentInstaller struct {
	name    string
	detect  func(home string) bool
	install func(home, hookCmd string) error
}

var installers = []agentInstaller{
	{"claude", dirExists(".claude"), installClaude},
	{"codex", func(h string) bool { _, err := os.Stat(codexHome(h)); return err == nil }, installCodex},
	{"gemini", fileExists(".gemini", "settings.json"), installGemini},
	{"antigravity", func(h string) bool {
		return dirExists(".gemini", "config")(h) || dirExists(".gemini", "antigravity")(h) || dirExists(".gemini", "antigravity-cli")(h)
	}, installAntigravity},
}

func dirExists(rel ...string) func(string) bool {
	return func(home string) bool {
		fi, err := os.Stat(filepath.Join(append([]string{home}, rel...)...))
		return err == nil && fi.IsDir()
	}
}

func fileExists(rel ...string) func(string) bool {
	return func(home string) bool {
		_, err := os.Stat(filepath.Join(append([]string{home}, rel...)...))
		return err == nil
	}
}

// hookFile is where each agent's hook (or, for Claude, plugin) is configured.
func hookFile(agent, home string) string {
	switch agent {
	case "claude":
		return filepath.Join(home, ".claude", "settings.json")
	case "codex":
		return filepath.Join(codexHome(home), "hooks.json")
	case "gemini":
		return filepath.Join(home, ".gemini", "settings.json")
	}
	return filepath.Join(home, ".gemini", "config", "hooks.json")
}

func codexHome(home string) string {
	if d := os.Getenv("CODEX_HOME"); d != "" {
		return d
	}
	return filepath.Join(home, ".codex")
}

// hookCommand is quoted with forward slashes so it works from sh, Git Bash
// and cmd.exe alike.
func hookCommand(agent string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return `"` + filepath.ToSlash(exe) + `" hook ` + agent, nil
}

func cmdInstallHooks(args []string) int {
	names := make([]string, len(installers))
	for i, in := range installers {
		names[i] = in.name
	}
	if len(args) != 1 {
		return errf(2, "usage: agentssh install-hooks %s|all", strings.Join(names, "|"))
	}
	home, _ := os.UserHomeDir()
	done := 0
	for _, in := range installers {
		if args[0] != in.name && !(args[0] == "all" && in.detect(home)) {
			continue
		}
		cmd, err := hookCommand(in.name)
		if err == nil {
			err = in.install(home, cmd)
		}
		if err != nil {
			return errf(1, "%s: %v", in.name, err)
		}
		done++
	}
	if done == 0 {
		return errf(2, "nothing installed: unknown agent %q or no agent config found (agents: %s)", args[0], strings.Join(names, ", "))
	}
	return 0
}

// editJSON loads a JSON object (missing file = empty), lets f change it and
// writes it back when f reports a change. Unknown keys are preserved.
func editJSON(p string, f func(m map[string]any) bool) error {
	m := map[string]any{}
	if b, err := os.ReadFile(p); err == nil {
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !f(m) {
		return nil
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, append(b, '\n'), 0o600)
}

func child(m map[string]any, k string) map[string]any {
	v, ok := m[k].(map[string]any)
	if !ok {
		v = map[string]any{}
		m[k] = v
	}
	return v
}

// addHookEntry appends {matcher, hooks:[hook]} to m[event] unless an
// agentssh hook is already there.
func addHookEntry(m map[string]any, event, matcher string, hook map[string]any) bool {
	list, _ := m[event].([]any)
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), "agentssh") && strings.Contains(string(b), " hook ") {
		return false
	}
	m[event] = append(list, map[string]any{"matcher": matcher, "hooks": []any{hook}})
	return true
}

// addStrings appends missing values to the string list m[k].
func addStrings(m map[string]any, k string, vals ...string) bool {
	list, _ := m[k].([]any)
	changed := false
	for _, v := range vals {
		found := false
		for _, x := range list {
			found = found || x == v
		}
		if !found {
			list = append(list, v)
			changed = true
		}
	}
	m[k] = list
	return changed
}

func writeSkill(dir string) error {
	return writeFile(filepath.Join(dir, "agentssh", "SKILL.md"), plugin.Skill)
}

// --- Claude Code: skill, PreToolUse hook, permissions.deny ---

func addClaudeHook(settings map[string]any, command string) bool {
	changed := addHookEntry(child(settings, "hooks"), "PreToolUse", "Bash|Edit|Write|MultiEdit|NotebookEdit",
		map[string]any{"type": "command", "command": command, "timeout": 10})
	var deny []string
	for _, t := range sshTools {
		deny = append(deny, "Bash("+t+":*)")
	}
	return addStrings(child(settings, "permissions"), "deny", deny...) || changed
}

func installClaude(home, hookCmd string) error {
	if err := writeSkill(filepath.Join(home, ".claude", "skills")); err != nil {
		return err
	}
	p := filepath.Join(home, ".claude", "settings.json")
	if err := editJSON(p, func(m map[string]any) bool { return addClaudeHook(m, hookCmd) }); err != nil {
		return err
	}
	fmt.Println("Claude Code: skill, PreToolUse hook and ssh deny rules in", p)
	fmt.Println("  (alternative: /plugin marketplace add ASromancer/agentssh, then /plugin install agentssh@agentssh)")
	return nil
}

// --- Codex: skill, AGENTS.md block, hooks.json, execpolicy rules ---

const (
	codexBegin = "<!-- agentssh:begin -->"
	codexEnd   = "<!-- agentssh:end -->"
)

const codexBlock = codexBegin + `
## Remote servers: agentssh

Never call ssh, scp, sftp, rsync (to remote hosts) or mosh directly. Use agentssh (see the agentssh skill):
` + "`agentssh hosts`, `agentssh run <host> \"<cmd>\"`, `agentssh out <id> --grep <re>`" + `.
Exit 100 = blocked by policy, 101 = denied by the user or timed out, 102 = daemon down or vault locked.
On 101 stop and ask the user; never retry another way. Never run agentssh approve/key/reload/host/init/unlock.
` + codexEnd + "\n"

func codexRules() string {
	var b strings.Builder
	b.WriteString("# Installed by agentssh. Direct SSH bypasses agentssh's policy and approvals.\n")
	for _, t := range sshTools {
		fmt.Fprintf(&b, "prefix_rule(pattern=[%q], decision=\"forbidden\", justification=\"Use agentssh run <host> <cmd> instead of %s\")\n", t, t)
	}
	for _, s := range humanOnlySubs {
		fmt.Fprintf(&b, "prefix_rule(pattern=[\"agentssh\", %q], decision=\"forbidden\", justification=\"agentssh %s is for the human user only\")\n", s, s)
	}
	return b.String()
}

func installCodex(home, hookCmd string) error {
	ch := codexHome(home)
	if err := writeSkill(filepath.Join(home, ".agents", "skills")); err != nil {
		return err
	}
	p := filepath.Join(ch, "AGENTS.md")
	old, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s := string(old)
	if i, j := strings.Index(s, codexBegin), strings.Index(s, codexEnd); i >= 0 && j > i {
		s = s[:i] + strings.TrimSuffix(codexBlock, "\n") + s[j+len(codexEnd):]
	} else {
		if s != "" && !strings.HasSuffix(s, "\n") {
			s += "\n"
		}
		s += "\n" + codexBlock
	}
	if err := writeFile(p, s); err != nil {
		return err
	}
	if err := editJSON(filepath.Join(ch, "hooks.json"), func(m map[string]any) bool {
		return addHookEntry(child(m, "hooks"), "PreToolUse", ".*",
			map[string]any{"type": "command", "command": hookCmd, "timeout": 30})
	}); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(ch, "rules", "agentssh.rules"), codexRules()); err != nil {
		return err
	}
	fmt.Println("Codex: skill in ~/.agents/skills, AGENTS.md block, hooks.json and rules/agentssh.rules in", ch)
	fmt.Println("  run /hooks in Codex once to review and trust the agentssh hook")
	return nil
}

// --- Gemini CLI: skill, BeforeTool hook, policy ---

func geminiPolicy() string {
	var b strings.Builder
	b.WriteString("# Installed by agentssh. Direct SSH bypasses agentssh's policy and approvals.\n")
	for _, t := range sshTools {
		fmt.Fprintf(&b, "\n[[rule]]\ntoolName = \"run_shell_command\"\ncommandPrefix = %q\ndecision = \"deny\"\npriority = 900\ndenyMessage = \"Use agentssh run <host> <cmd> instead of %s\"\n", t, t)
	}
	for _, s := range humanOnlySubs {
		fmt.Fprintf(&b, "\n[[rule]]\ntoolName = \"run_shell_command\"\ncommandPrefix = \"agentssh %s\"\ndecision = \"deny\"\npriority = 900\ndenyMessage = \"agentssh %s is for the human user only\"\n", s, s)
	}
	return b.String()
}

func installGemini(home, hookCmd string) error {
	if err := writeSkill(filepath.Join(home, ".agents", "skills")); err != nil {
		return err
	}
	p := filepath.Join(home, ".gemini", "settings.json")
	if err := editJSON(p, func(m map[string]any) bool {
		return addHookEntry(child(m, "hooks"), "BeforeTool", "run_shell_command|write_file|replace",
			map[string]any{"name": "agentssh", "type": "command", "command": hookCmd, "timeout": 30000})
	}); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(home, ".gemini", "policies", "agentssh.toml"), geminiPolicy()); err != nil {
		return err
	}
	fmt.Println("Gemini CLI: skill in ~/.agents/skills, BeforeTool hook in", p, "and policies/agentssh.toml")
	return nil
}

// --- Antigravity (app, IDE, agy CLI): skill, hooks.json, CLI permissions ---

func installAntigravity(home, hookCmd string) error {
	cfg := filepath.Join(home, ".gemini", "config")
	if err := writeSkill(filepath.Join(cfg, "skills")); err != nil {
		return err
	}
	hooksPath := filepath.Join(cfg, "hooks.json")
	if err := editJSON(hooksPath, func(m map[string]any) bool {
		group := map[string]any{"PreToolUse": []any{map[string]any{"matcher": "run_command",
			"hooks": []any{map[string]any{"type": "command", "command": hookCmd, "timeout": 30}}}}}
		b1, _ := json.Marshal(m["agentssh"])
		b2, _ := json.Marshal(group)
		m["agentssh"] = group
		return string(b1) != string(b2)
	}); err != nil {
		return err
	}
	var deny []string
	for _, t := range sshTools {
		deny = append(deny, "command("+t+")")
	}
	for _, s := range humanOnlySubs {
		deny = append(deny, "command(agentssh "+s+")")
	}
	perm := filepath.Join(home, ".gemini", "antigravity-cli", "settings.json")
	if err := editJSON(perm, func(m map[string]any) bool { return addStrings(child(m, "permissions"), "deny", deny...) }); err != nil {
		return err
	}
	fmt.Println("Antigravity: skill in", filepath.Join(cfg, "skills"), "hook in", hooksPath, "and CLI deny rules in", perm)
	fmt.Println("  (the app/IDE take command deny rules from Settings; add ssh/scp there too)")
	return nil
}
