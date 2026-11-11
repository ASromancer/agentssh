package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAddClaudeHookIdempotent(t *testing.T) {
	s := map[string]any{}
	json.Unmarshal([]byte(`{"model":"x","permissions":{"deny":["Bash(ssh:*)"]}}`), &s)
	if !addClaudeHook(s, "/bin/agentssh hook claude") {
		t.Fatal("first install changed nothing")
	}
	if addClaudeHook(s, "/bin/agentssh hook claude") {
		t.Fatal("second install changed settings")
	}
	b, _ := json.Marshal(s)
	if !strings.Contains(string(b), `"model":"x"`) || strings.Count(string(b), "Bash(ssh:*)") != 1 ||
		!strings.Contains(string(b), "/bin/agentssh hook claude") {
		t.Fatalf("%s", b)
	}
}
