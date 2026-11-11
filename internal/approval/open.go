package approval

import (
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ASromancer/agentssh/internal/humanok"
)

// LocalURL reports whether u is a plain http URL on this machine's
// loopback; only those are ever opened.
func LocalURL(u string) bool {
	if strings.ContainsAny(u, " \t\r\n") {
		return false
	}
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "http" {
		return false
	}
	h := p.Hostname()
	return h == "127.0.0.1" || strings.EqualFold(h, "localhost")
}

// OpenURL opens a loopback URL in the user's browser with the platform's
// opener from a root-owned system path.
func OpenURL(u string) error {
	if !LocalURL(u) {
		return errors.New("refusing to open a non-local URL")
	}
	var bin string
	var args []string
	var err error
	switch runtime.GOOS {
	case "linux":
		bin, err = humanok.TrustedBinary("/usr/bin/xdg-open", "/bin/xdg-open")
		args = []string{u}
	case "darwin":
		bin, err = humanok.TrustedBinary("/usr/bin/open")
		args = []string{u}
	case "windows":
		bin, err = humanok.TrustedBinary(filepath.Join(humanok.SystemDir(), "rundll32.exe"))
		args = []string{"url.dll,FileProtocolHandler", u}
	default:
		return errors.New("cannot open a browser on " + runtime.GOOS)
	}
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = openEnv(os.Environ(), runtime.GOOS)
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}

// openEnv keeps the session variables an opener needs. The daemon's
// environment is not trusted: BROWSER, LD_PRELOAD and PATH never reach it.
func openEnv(environ []string, goos string) []string {
	keep := []string{"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR",
		"XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE", "XDG_DATA_DIRS", "XDG_CONFIG_DIRS", "HOME", "LANG", "LC_ALL"}
	if goos == "windows" {
		keep = append(keep, "SystemRoot", "USERPROFILE", "TEMP", "TMP", "LOCALAPPDATA", "APPDATA")
	}
	var out []string
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		for _, w := range keep {
			if k == w || (goos == "windows" && strings.EqualFold(k, w)) {
				out = append(out, kv)
				break
			}
		}
	}
	if goos != "windows" {
		out = append(out, "PATH=/usr/local/bin:/usr/bin:/bin")
	}
	return out
}
