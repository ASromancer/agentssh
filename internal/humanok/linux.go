//go:build linux && !e2efake

package humanok

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
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

var runPkcheck = func(ctx context.Context, args ...string) (int, string, error) {
	out, err := exec.CommandContext(ctx, "pkcheck", args...).CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out), nil
	}
	if err != nil {
		return -1, string(out), err
	}
	return 0, string(out), nil
}

func (platform) Available() error {
	if _, err := os.Stat(PolicyPath); err != nil {
		return fmt.Errorf("%w: polkit action not installed (run: sudo agentssh install-polkit)", ErrUnavailable)
	}
	if _, err := exec.LookPath("pkcheck"); err != nil {
		return fmt.Errorf("%w: pkcheck not found (install polkit)", ErrUnavailable)
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return fmt.Errorf("%w: no graphical session", ErrUnavailable)
	}
	return nil
}

func (platform) Confirm(ctx context.Context, msg string) error {
	code, out, err := runPkcheck(ctx, "--action-id", ActionID, "--process", strconv.Itoa(os.Getpid()),
		"--allow-user-interaction", "--detail", "message", msg)
	return pkResult(code, out, err)
}

func pkResult(code int, out string, err error) error {
	switch {
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
