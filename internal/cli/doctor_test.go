package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	t.Setenv("OSTIARY_SOCKET", filepath.Join(t.TempDir(), "none.sock"))
	checks := doctorChecks(false)
	if len(checks) == 0 || checks[0].OK || !strings.Contains(checks[0].Text, "daemon is not running") {
		t.Fatalf("%+v", checks)
	}
}

func TestDetachArgs(t *testing.T) {
	if got := detachArgs(false, false, 0, 0); len(got) != 0 {
		t.Fatalf("defaults: %v", got)
	}
	if got := strings.Join(detachArgs(true, true, 8080, 0), " "); got != "--no-ui --no-tray --ui-port 8080" {
		t.Fatalf("got %q", got)
	}
}

func TestDialRetryWaits(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("OSTIARY_SOCKET", filepath.Join(t.TempDir(), "none.sock"))
	start := time.Now()
	if _, err := dialRetry(0); err == nil || time.Since(start) > 150*time.Millisecond {
		t.Fatalf("wait=0 must fail fast: %v", err)
	}
	start = time.Now()
	if _, err := dialRetry(600 * time.Millisecond); err == nil || time.Since(start) < 300*time.Millisecond {
		t.Fatalf("should retry: %v %v", err, time.Since(start))
	}
}
