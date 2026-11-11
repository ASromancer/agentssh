// Package humanok asks the operating system to confirm that the person at
// the machine approves an action: polkit on Linux, LocalAuthentication on
// macOS, the Windows credential prompt on Windows. The daemon calls it, so
// a caller of the daemon's API (GUI, CLI or an agent) still cannot approve
// anything without the human passing the OS dialog.
package humanok

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
)

var (
	ErrDenied      = errors.New("not confirmed by the user")
	ErrUnavailable = errors.New("OS authentication unavailable")
)

// Confirmer shows an OS authentication dialog.
type Confirmer interface {
	// Available returns nil when Confirm can show a dialog right now.
	Available() error
	// Confirm returns nil only if the user authenticated for msg.
	Confirm(ctx context.Context, msg string) error
}

// Default is the platform implementation.
var Default Confirmer = platform{}

// Fake is a Confirmer for tests.
type Fake struct {
	Err        error // returned by Available
	ConfirmErr error // if set, returned by Confirm
	Allow      bool

	mu   sync.Mutex
	msgs []string
}

func (f *Fake) Available() error { return f.Err }

func (f *Fake) Confirm(_ context.Context, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, msg)
	if f.ConfirmErr != nil {
		return f.ConfirmErr
	}
	if f.Allow {
		return nil
	}
	return ErrDenied
}

func (f *Fake) Msgs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.msgs...)
}

// polkit action used on Linux.
const (
	ActionID   = "dev.ostiary.confirm"
	PolicyPath = "/usr/share/polkit-1/actions/dev.ostiary.policy"
)

// PolicyXML is the polkit action installed by 'sudo ostiary install-polkit'.
// auth_self (not auth_self_keep): every action needs its own
// authentication. polkit only lets uid 0 or an action owner pass details
// (the $(message) text), so the installing user is the owner.
func PolicyXML(owner string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>ostiary</vendor>
  <vendor_url>https://github.com/ASromancer/ostiary</vendor_url>
  <action id="dev.ostiary.confirm">
    <description>Confirm an Ostiary action</description>
    <message>Ostiary: $(message)</message>
    <defaults>
      <allow_any>auth_self</allow_any>
      <allow_inactive>auth_self</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.owner">unix-user:` + owner + `</annotate>
  </action>
</policyconfig>
`
}

// InstallPolicy writes the polkit action owned by the user who ran sudo.
// Linux only; needs root.
func InstallPolicy() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("polkit is only used on Linux; nothing to install on %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("run it with sudo: sudo ostiary install-polkit")
	}
	owner := os.Getenv("SUDO_USER")
	if owner == "" || owner == "root" || strings.ContainsAny(owner, "<>&\"'") {
		return errors.New("run it with sudo from your own account (SUDO_USER must name you)")
	}
	return os.WriteFile(PolicyPath, []byte(PolicyXML(owner)), 0o644)
}
