package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ASromancer/ostiary/internal/paths"
)

func TestReadOutput(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	os.MkdirAll(paths.Out(), 0o700)
	os.WriteFile(filepath.Join(paths.Out(), "7"), []byte("a\nerr one\nb\nerr two\n"), 0o600)
	if got, _ := ReadOutput(7, "^err", ""); got != "2: err one\n4: err two\n" {
		t.Fatalf("grep: %q", got)
	}
	if got, _ := ReadOutput(7, "", "2:3"); got != "err one\nb\n" {
		t.Fatalf("range: %q", got)
	}
	if _, err := ReadOutput(8, "", ""); err == nil {
		t.Fatal("missing id")
	}
}
