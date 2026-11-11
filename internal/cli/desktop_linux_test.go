//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ASromancer/ostiary/internal/brand"
)

func TestInstallDesktop(t *testing.T) {
	home := t.TempDir()
	if err := installDesktop(home, "/opt/o s/ostiary"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(home, ".local/share/applications/ostiary.desktop"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Desktop Entry]", "Name=Ostiary", `Exec="/opt/o s/ostiary" open`, "Icon=ostiary", "Terminal=false", "Type=Application"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q in\n%s", want, b)
		}
	}
	p, _ := os.ReadFile(filepath.Join(home, ".local/share/icons/hicolor/256x256/apps/ostiary.png"))
	if string(p) != string(brand.PNG(256)) {
		t.Fatal("icon not written")
	}
}
