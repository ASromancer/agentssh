//go:build linux && !e2efake

package humanok

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

type platform struct{}

// pkcheck(1) exit codes.
const (
	pkAuthorized    = 0
	pkNotAuthorized = 1
	pkChallenge     = 2 // authorization needs interaction that could not happen
	pkDismissed     = 3
)

// pkcheckPaths are the only places pkcheck is run from; never PATH.
var pkcheckPaths = []string{"/usr/bin/pkcheck", "/bin/pkcheck"}

var runPkcheck = func(ctx context.Context, args ...string) (int, string, error) {
	pk, err := TrustedBinary(pkcheckPaths...)
	if err != nil {
		return -1, "", err
	}
	out, err := pkcheckCmd(ctx, pk, args...).CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out), nil
	}
	if err != nil {
		return -1, string(out), err
	}
	return 0, string(out), nil
}

// pkcheckCmd runs pkcheck with an empty environment. The daemon's
// environment is not trusted (an agent can change it with systemctl --user
// set-environment and restart the daemon): LD_PRELOAD or
// DBUS_SYSTEM_BUS_ADDRESS would decide the answer. pkcheck needs none of it.
func pkcheckCmd(ctx context.Context, pk string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, pk, args...)
	cmd.Env = []string{} // non-nil: nil would inherit
	return cmd
}

func (platform) Available() error {
	policy, err := os.ReadFile(PolicyPath)
	if err != nil {
		return fmt.Errorf("%w: polkit action not installed (run: sudo ostiary install-polkit)", ErrUnavailable)
	}
	if _, err := TrustedBinary(pkcheckPaths...); err != nil {
		return fmt.Errorf("%w: pkcheck: %v (install polkit)", ErrUnavailable, err)
	}
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return setupProblem(policy, name, os.Getenv, func(p string) bool { _, err := os.Stat(p); return err == nil })
}

// setupProblem checks that the installed polkit action belongs to user
// (polkit refuses the dialog text otherwise) and that the session has a
// local display where the polkit agent can show its dialog.
func setupProblem(policy []byte, user string, getenv func(string) string, exists func(string) bool) error {
	if user == "" || !strings.Contains(string(policy), "unix-user:"+user+"<") {
		return fmt.Errorf("%w: polkit action belongs to another user (run sudo ostiary install-polkit as yourself)", ErrUnavailable)
	}
	if w := getenv("WAYLAND_DISPLAY"); w != "" {
		p := w
		if !filepath.IsAbs(p) {
			p = filepath.Join(getenv("XDG_RUNTIME_DIR"), w)
		}
		if !exists(p) {
			return fmt.Errorf("%w: Wayland display %s not found", ErrUnavailable, p)
		}
		return nil
	}
	d := getenv("DISPLAY")
	if d == "" {
		return fmt.Errorf("%w: no graphical session", ErrUnavailable)
	}
	n, ok := strings.CutPrefix(d, ":")
	n, screen, _ := strings.Cut(n, ".")
	if !ok || !digits(n) || (screen != "" && !digits(screen)) {
		return fmt.Errorf("%w: display %s is not local (forwarded displays cannot show the dialog)", ErrUnavailable, d)
	}
	if !exists("/tmp/.X11-unix/X" + n) {
		return fmt.Errorf("%w: X display %s not found", ErrUnavailable, d)
	}
	return nil
}

func digits(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

func (platform) Confirm(ctx context.Context, msg string) error {
	code, out, err := runPkcheck(ctx, "--action-id", ActionID, "--process", strconv.Itoa(os.Getpid()),
		"--allow-user-interaction", "--detail", "message", msg)
	return pkResult(code, out, err, ctx.Err() != nil)
}

// pkResult maps pkcheck's outcome to an error. killed means the context
// ended; a pkcheck killed by a signal (exit code -1) counts the same. Both
// are refusals, never ErrUnavailable: an agent must not be able to force
// the weaker code mode by killing pkcheck or leaving a dialog open.
func pkResult(code int, out string, err error, killed bool) error {
	switch {
	case killed || (err == nil && code == -1):
		return fmt.Errorf("%w: confirmation dialog timed out or was interrupted", ErrDenied)
	case err != nil:
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	case code == pkAuthorized:
		return nil
	case code == pkNotAuthorized || code == pkDismissed:
		return ErrDenied
	case code == pkChallenge:
		return fmt.Errorf("%w: no polkit authentication agent for this session", ErrUnavailable)
	}
	return fmt.Errorf("%w: pkcheck exit %d: %s", ErrUnavailable, code, strings.TrimSpace(out))
}
