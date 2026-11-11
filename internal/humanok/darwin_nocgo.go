//go:build darwin && !cgo && !e2efake

package humanok

import (
	"context"
	"fmt"
)

type platform struct{}

func (platform) Available() error {
	return fmt.Errorf("%w: this build has no cgo; use the official macOS release", ErrUnavailable)
}
func (platform) Confirm(context.Context, string) error { return ErrUnavailable }
