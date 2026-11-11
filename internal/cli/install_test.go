package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestAddClaudeHookIdempotent(t *testing.T) {
	s := map[string]any{}
	json.Unmarshal([]byte(`{"model":"x","permissions":{"deny":["Bash(ssh:*)"]}}`), &s)
	if !addClaudeHook(s, "/bin/ostiary hook claude") {
		t.Fatal("first install changed nothing")
	}
	if addClaudeHook(s, "/bin/ostiary hook claude") {
		t.Fatal("second install changed settings")
	}
	b, _ := json.Marshal(s)
	if !strings.Contains(string(b), `"model":"x"`) || strings.Count(string(b), "Bash(ssh:*)") != 1 ||
		!strings.Contains(string(b), "/bin/ostiary hook claude") {
		t.Fatalf("%s", b)
	}
}

func TestInstallAllAgents(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CODEX_HOME", "")
	for _, in := range installers {
		for i := 0; i < 2; i++ { // second run must not duplicate anything
			if err := in.install(home, `"/bin/ostiary" hook `+in.name); err != nil {
				t.Fatalf("%s: %v", in.name, err)
			}
		}
		b, err := os.ReadFile(hookFile(in.name, home))
		if err != nil || strings.Count(string(b), "hook "+in.name) != 1 {
			t.Errorf("%s hook file: %v\n%s", in.name, err, b)
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			t.Errorf("%s: invalid JSON", in.name)
		}
		if !in.detect(home) {
			t.Errorf("%s not detected after install", in.name)
		}
	}
	for _, p := range []string{".claude/skills/ostiary/SKILL.md", ".agents/skills/ostiary/SKILL.md",
		".gemini/config/skills/ostiary/SKILL.md", ".codex/rules/ostiary.rules", ".gemini/policies/ostiary.toml"} {
		if _, err := os.Stat(filepath.Join(home, p)); err != nil {
			t.Error(err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(home, ".codex", "AGENTS.md")); strings.Count(string(b), codexBegin) != 1 {
		t.Errorf("AGENTS.md block duplicated:\n%s", b)
	}
	var pol map[string]any
	if _, err := toml.DecodeFile(filepath.Join(home, ".gemini", "policies", "ostiary.toml"), &pol); err != nil {
		t.Errorf("gemini policy is not valid TOML: %v", err)
	}
}
