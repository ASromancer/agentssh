package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOldUnit(t *testing.T) {
	d := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(d, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if !oldUnit(write("old", "[Install]\nWantedBy=default.target\n")) {
		t.Error("old unit not flagged")
	}
	if oldUnit(write("new", "WantedBy=graphical-session.target\n")) {
		t.Error("new unit flagged")
	}
	if oldUnit(filepath.Join(d, "missing")) {
		t.Error("missing unit flagged")
	}
}
