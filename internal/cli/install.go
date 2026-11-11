package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ASromancer/ostiary/internal/daemon"
	"github.com/ASromancer/ostiary/internal/hook"
	"github.com/ASromancer/ostiary/plugin"
)

// Per-agent integration: skill, pre-tool hook, and a deny rule for direct
// ssh in the agent's own permission system. Formats follow each agent's
// docs as of 2026-11; see README "Agents".

var sshTools = []string{"ssh", "scp", "sftp", "mosh", "slogin"}
var humanOnlySubs = hook.HumanOnly

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

// hookInstalled reports whether an Ostiary hook (or the Claude plugin) is
// configured for agent under home.
func hookInstalled(agent, home string) bool {
	b, err := os.ReadFile(hookFile(agent, home))
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, " hook "+agent) && strings.Contains(s, "ostiary") ||
		agent == "claude" && strings.Contains(s, `"ostiary@`)
}

func agentStatesIn(home string) []daemon.AgentState {
	out := make([]daemon.AgentState, 0, len(installers))
	for _, in := range installers {
		out = append(out, daemon.AgentState{Name: in.name, Detected: in.detect(home), Installed: hookInstalled(in.name, home)})
	}
	return out
}

func installHookFor(agent string) error {
	home, _ := os.UserHomeDir()
	for _, in := range installers {
		if in.name == agent {
			cmd, err := hookCommand(agent)
			if err != nil {
				return err
			}
			return in.install(home, cmd)
		}
	}
	return fmt.Errorf("unknown agent %q", agent)
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
	exe, err := cliExe()
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
		return errf(2, "usage: ostiary install-hooks %s|all", strings.Join(names, "|"))
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
// ostiary hook is already there.
func addHookEntry(m map[string]any, event, matcher string, hook map[string]any) bool {
	list, _ := m[event].([]any)
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), "ostiary") && strings.Contains(string(b), " hook ") {
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
	return writeFile(filepath.Join(dir, "ostiary", "SKILL.md"), plugin.Skill)
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
	fmt.Println("  (alternative: /plugin marketplace add ASromancer/ostiary, then /plugin install ostiary@ostiary)")
	return nil
}

// --- Codex: skill, AGENTS.md block, hooks.json, execpolicy rules ---

const (
	codexBegin = "<!-- ostiary:begin -->"
	codexEnd   = "<!-- ostiary:end -->"
)

const codexBlock = codexBegin + `
## Remote servers: ostiary

Never call ssh, scp, sftp, rsync (to remote hosts) or mosh directly. Use ostiary (see the ostiary skill):
` + "`ostiary hosts`, `ostiary run <host> \"<cmd>\"`, `ostiary out <id> --grep <re>`" + `.
Exit 100 = blocked by policy, 101 = denied by the user or timed out, 102 = daemon down or vault locked.
On 101 stop and ask the user; never retry another way. On 102 inside the sandbox, first re-run the same ostiary command outside the sandbox (escalated): the sandbox blocks ostiary's local daemon socket. Never run (also as ostiary-app) approve, key, reload, host, init, unlock, install-hooks, daemon, ui, open, stop, upgrade, install-service, uninstall-service.
` + codexEnd + "\n"

// refreshCodexRules rewrites our Codex rules file when it is already
// installed, so an upgrade brings new rules without re-running install-hooks.
func refreshCodexRules(home string) {
	p := filepath.Join(codexHome(home), "rules", "ostiary.rules")
	if b, err := os.ReadFile(p); err == nil && string(b) != codexRules() {
		_ = writeFile(p, codexRules())
	}
}

func codexRules() string {
	var b strings.Builder
	b.WriteString("# Installed by ostiary. Direct SSH bypasses ostiary's policy and approvals.\n")
	for _, t := range sshTools {
		fmt.Fprintf(&b, "prefix_rule(pattern=[%q], decision=\"forbidden\", justification=\"Use ostiary run <host> <cmd> instead of %s\")\n", t, t)
	}
	for _, bin := range hook.Binaries {
		for _, s := range humanOnlySubs {
			fmt.Fprintf(&b, "prefix_rule(pattern=[%q, %q], decision=\"forbidden\", justification=\"%s %s is for the human user only\")\n", bin, s, bin, s)
		}
	}
	// Codex's sandbox blocks the daemon's local socket, so ostiary must run
	// outside it. The daemon still classifies, approves and audits every
	// command; the forbidden rules above win over this one (strictest wins).
	b.WriteString("prefix_rule(pattern=[\"ostiary\"], decision=\"allow\", justification=\"ostiary is the SSH gate; it must reach its local daemon outside the sandbox\")\n")
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
	if err := writeFile(filepath.Join(ch, "rules", "ostiary.rules"), codexRules()); err != nil {
		return err
	}
	fmt.Println("Codex: skill in ~/.agents/skills, AGENTS.md block, hooks.json and rules/ostiary.rules in", ch)
	fmt.Println("  run /hooks in Codex once to review and trust the ostiary hook")
	return nil
}

// --- Gemini CLI: skill, BeforeTool hook, policy ---

func geminiPolicy() string {
	var b strings.Builder
	b.WriteString("# Installed by ostiary. Direct SSH bypasses ostiary's policy and approvals.\n")
	for _, t := range sshTools {
		fmt.Fprintf(&b, "\n[[rule]]\ntoolName = \"run_shell_command\"\ncommandPrefix = %q\ndecision = \"deny\"\npriority = 900\ndenyMessage = \"Use ostiary run <host> <cmd> instead of %s\"\n", t, t)
	}
	for _, bin := range hook.Binaries {
		for _, s := range humanOnlySubs {
			fmt.Fprintf(&b, "\n[[rule]]\ntoolName = \"run_shell_command\"\ncommandPrefix = \"%s %s\"\ndecision = \"deny\"\npriority = 900\ndenyMessage = \"%s %s is for the human user only\"\n", bin, s, bin, s)
		}
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
			map[string]any{"name": "ostiary", "type": "command", "command": hookCmd, "timeout": 30000})
	}); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(home, ".gemini", "policies", "ostiary.toml"), geminiPolicy()); err != nil {
		return err
	}
	fmt.Println("Gemini CLI: skill in ~/.agents/skills, BeforeTool hook in", p, "and policies/ostiary.toml")
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
		b1, _ := json.Marshal(m["ostiary"])
		b2, _ := json.Marshal(group)
		m["ostiary"] = group
		return string(b1) != string(b2)
	}); err != nil {
		return err
	}
	var deny []string
	for _, t := range sshTools {
		deny = append(deny, "command("+t+")")
	}
	for _, bin := range hook.Binaries {
		for _, s := range humanOnlySubs {
			deny = append(deny, "command("+bin+" "+s+")")
		}
	}
	perm := filepath.Join(home, ".gemini", "antigravity-cli", "settings.json")
	if err := editJSON(perm, func(m map[string]any) bool { return addStrings(child(m, "permissions"), "deny", deny...) }); err != nil {
		return err
	}
	fmt.Println("Antigravity: skill in", filepath.Join(cfg, "skills"), "hook in", hooksPath, "and CLI deny rules in", perm)
	fmt.Println("  (the app/IDE take command deny rules from Settings; add ssh/scp there too)")
	return nil
}
