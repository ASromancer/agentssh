package paths

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestWithin(t *testing.T) {
	base := filepath.Join(t.TempDir(), "agentssh")
	for _, tc := range []struct {
		p    string
		want bool
	}{
		{base, true},
		{filepath.Join(base, "vault.bin"), true},
		{filepath.Join(base, "..", "agentssh", "x"), true},
		{base + "-other", false},
		{filepath.Dir(base), false},
	} {
		if got := Within(tc.p, base); got != tc.want {
			t.Errorf("Within(%q): got %v", tc.p, got)
		}
	}
	if runtime.GOOS == "windows" && !Within(filepath.Join(base, "X"), filepath.Dir(base)+`\AGENTSSH`) {
		t.Error("expected case-insensitive match on Windows")
	}
}
