package humanok

import (
	"errors"
	"fmt"
	"path/filepath"
)

// TrustedBinary returns the first candidate that only an administrator
// can have put there: an absolute path to a regular file that, with every
// parent directory, is owned by root and not writable by group or others
// (on Windows: a file under %SystemRoot%). System helpers are never found
// through PATH, which an agent can change to run its own "pkcheck".
func TrustedBinary(candidates ...string) (string, error) {
	err := errors.New("no candidates")
	for _, c := range candidates {
		if !filepath.IsAbs(c) {
			err = fmt.Errorf("%s is not an absolute path", c)
			continue
		}
		var p string
		if p, err = trusted(filepath.Clean(c)); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no trusted system binary among %v: %w", candidates, err)
}
