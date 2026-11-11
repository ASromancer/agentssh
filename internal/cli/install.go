package cli

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed skill.md
var skillMD string

const (
	hookMatcher  = "Bash|Edit|Write|MultiEdit|NotebookEdit"
	codexBegin   = "<!-- agentssh:begin -->"
	codexEnd     = "<!-- agentssh:end -->"
	settingsPerm = 0o600
)

var sshDenyRules = []string{"Bash(ssh:*)", "Bash(scp:*)", "Bash(sftp:*)", "Bash(mosh:*)"}

func cmdInstallHooks(args []string) int {
	if len(args) != 1 {
		return errf(2, "usage: agentssh install-hooks claude|codex")
	}
	var err error
	switch args[0] {
	case "claude":
		err = installClaude()
	case "codex":
		err = installCodex()
	default:
		return errf(2, "unknown agent %q (claude|codex)", args[0])
	}
	if err != nil {
		return errf(1, "%v", err)
	}
	return 0
}

// installClaude writes the skill and adds the PreToolUse hook plus deny
// rules for direct ssh to ~/.claude/settings.json, keeping everything else.
func installClaude() error {
	home, _ := os.UserHomeDir()
	if err := writeFile(filepath.Join(home, ".claude", "skills", "agentssh", "SKILL.md"), skillMD); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	p := filepath.Join(home, ".claude", "settings.json")
	settings := map[string]any{}
	if b, err := os.ReadFile(p); err == nil {
		if err := json.Unmarshal(b, &settings); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Quoted, forward slashes: works from sh, Git Bash and cmd.exe alike.
	if added := addClaudeHook(settings, `"`+filepath.ToSlash(exe)+`" hook claude`); added {
		b, _ := json.MarshalIndent(settings, "", "  ")
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, append(b, '\n'), settingsPerm); err != nil {
			return err
		}
	}
	fmt.Println("Claude Code: skill installed, PreToolUse hook and ssh deny rules in", p)
	return nil
}

// addClaudeHook mutates settings and reports whether anything changed.
func addClaudeHook(settings map[string]any, command string) bool {
	changed := false
	obj := func(m map[string]any, k string) map[string]any {
		v, ok := m[k].(map[string]any)
		if !ok {
			v = map[string]any{}
			m[k] = v
		}
		return v
	}
	hooks := obj(settings, "hooks")
	pre, _ := hooks["PreToolUse"].([]any)
	b, _ := json.Marshal(pre)
	if !strings.Contains(string(b), "hook claude") {
		pre = append(pre, map[string]any{
			"matcher": hookMatcher,
			"hooks":   []any{map[string]any{"type": "command", "command": command, "timeout": 10}},
		})
		hooks["PreToolUse"] = pre
		changed = true
	}
	perms := obj(settings, "permissions")
	deny, _ := perms["deny"].([]any)
	for _, r := range sshDenyRules {
		found := false
		for _, d := range deny {
			found = found || d == r
		}
		if !found {
			deny = append(deny, r)
			changed = true
		}
	}
	perms["deny"] = deny
	return changed
}

const codexBlock = codexBegin + `
## Remote servers: agentssh

Never call ssh, scp, sftp, rsync (to remote hosts) or mosh directly. Use agentssh:

- ` + "`agentssh hosts`" + ` lists usable hosts.
- ` + "`agentssh run <host> \"<cmd>\"`" + ` runs one command; ` + "`agentssh out <id> --grep <re>`" + ` reads full output.
- ` + "`agentssh get|put`" + ` copies files; ` + "`agentssh job start|tail|kill`" + ` for long commands;
  ` + "`agentssh explain \"<cmd>\"`" + ` shows the classification.
- Exit 100 = blocked by policy, 101 = denied by the user or timed out, 102 = daemon down or vault locked.
  On 101 stop and ask the user; never retry another way.
- Never run ` + "`agentssh approve|key|reload|host|init|unlock|install-hooks`" + `: they are for the human.
- No PTY: use ` + "`top -bn1`, `cat`, `tail -n`" + ` instead of interactive programs.
` + codexEnd + "\n"

// installCodex adds the instruction block to ~/.codex/AGENTS.md. Codex has
// no hook we rely on here; the daemon's hard layer still applies.
func installCodex() error {
	home, _ := os.UserHomeDir()
	p := filepath.Join(home, ".codex", "AGENTS.md")
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
	fmt.Println("Codex: instructions written to", p)
	return nil
}
