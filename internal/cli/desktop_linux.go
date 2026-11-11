//go:build linux

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ASromancer/ostiary/internal/brand"
)

func desktopEntry(exe string) string {
	return fmt.Sprintf("[Desktop Entry]\nType=Application\nName=Ostiary\n"+
		"Comment=Người gác cửa giữa AI agent và máy chủ của bạn\n"+
		"Exec=%q open\nIcon=ostiary\nTerminal=false\nCategories=Utility;Security;\nStartupNotify=false\n", exe)
}

// installDesktop adds Ostiary to the desktop's application menu.
func installDesktop(home, exe string) error {
	for _, n := range []int{16, 32, 48, 64, 128, 256, 512} {
		p := filepath.Join(home, ".local/share/icons/hicolor", fmt.Sprintf("%dx%d", n, n), "apps", "ostiary.png")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, brand.PNG(n), 0o644); err != nil {
			return err
		}
	}
	p := filepath.Join(home, ".local/share/applications", "ostiary.desktop")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(desktopEntry(exe)), 0o644); err != nil {
		return err
	}
	_ = exec.Command("update-desktop-database", filepath.Dir(p)).Run() // optional; menus also rescan
	return nil
}

// installDesktopUser is the install-service hook: the .deb (exe under /usr/)
// ships its own system entry; failure is only a warning.
func installDesktopUser(home, exe string) {
	if strings.HasPrefix(exe, "/usr/") {
		return
	}
	if err := installDesktop(home, exe); err != nil {
		fmt.Fprintln(os.Stderr, "warning: menu entry not installed:", err)
	}
}
