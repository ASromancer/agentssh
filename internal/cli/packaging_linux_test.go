//go:build linux

package cli

import (
	"os"
	"testing"
)

// The .deb ships a static copy of the unit; it must not drift from the code.
func TestPackagedServiceMatches(t *testing.T) {
	b, err := os.ReadFile("../../packaging/linux/ostiary.service")
	if err != nil {
		t.Fatal(err)
	}
	if want := systemdUnit("/usr/bin/ostiary"); string(b) != want {
		t.Errorf("packaging/linux/ostiary.service differs from systemdUnit:\n%s\nwant:\n%s", b, want)
	}
}
