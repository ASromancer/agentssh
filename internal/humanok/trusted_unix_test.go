//go:build unix

package humanok

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedBinary(t *testing.T) {
	mine := filepath.Join(t.TempDir(), "pkcheck")
	if err := os.WriteFile(mine, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if p, err := TrustedBinary(mine); err == nil {
		t.Fatalf("user-owned %s accepted as %s", mine, p)
	}
	if p, err := TrustedBinary("pkcheck"); err == nil {
		t.Fatalf("relative path accepted as %s", p)
	}
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	// A missing or untrusted candidate is skipped; the root-owned one wins.
	p, err := TrustedBinary("/nonexistent/pkcheck", mine, "/bin/sh")
	if err != nil || p != sh {
		t.Fatalf("got %q %v, want %s", p, err, sh)
	}
}
