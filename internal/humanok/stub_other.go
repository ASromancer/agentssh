//go:build !linux && !darwin && !e2efake

package humanok

import (
	"context"
	"fmt"
	"runtime"
)

type platform struct{}

func (platform) Available() error {
	return fmt.Errorf("%w: not implemented on %s yet", ErrUnavailable, runtime.GOOS)
}
func (platform) Confirm(context.Context, string) error { return ErrUnavailable }
