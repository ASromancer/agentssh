package cli

import (
	"os"
	"path/filepath"
	"strings"
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

func TestDoctorChecksShape(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("AGENTSSH_SOCKET", filepath.Join(t.TempDir(), "none.sock"))
	checks := doctorChecks(false)
	if len(checks) == 0 || checks[0].OK || !strings.Contains(checks[0].Text, "daemon is not running") {
		t.Fatalf("%+v", checks)
	}
}

func TestDetachArgs(t *testing.T) {
	if got := detachArgs(false, false, 0); len(got) != 0 {
		t.Fatalf("defaults: %v", got)
	}
	if got := strings.Join(detachArgs(true, true, 8080), " "); got != "--no-ui --no-tray --ui-port 8080" {
		t.Fatalf("got %q", got)
	}
}
