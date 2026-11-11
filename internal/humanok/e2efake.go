//go:build e2efake

package humanok

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Test-only confirmer: reads "allow", "deny" or "unavailable" from $OSTIARY_E2E_HUMANOK
// and appends each dialog text to that file + ".log". Never in releases.
type platform struct{}

func (platform) Available() error {
	if os.Getenv("OSTIARY_E2E_HUMANOK") == "" {
		return fmt.Errorf("%w: e2e fake not configured", ErrUnavailable)
	}
	return nil
}

func (platform) Confirm(_ context.Context, msg string) error {
	p := os.Getenv("OSTIARY_E2E_HUMANOK")
	f, err := os.OpenFile(p+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		fmt.Fprintln(f, msg)
		f.Close()
	}
	b, _ := os.ReadFile(p)
	switch strings.TrimSpace(string(b)) {
	case "allow":
		return nil
	case "unavailable":
		return fmt.Errorf("%w: e2e fake dialog broke", ErrUnavailable)
	}
	return ErrDenied
}
