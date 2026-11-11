//go:build unix

package humanok

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// trusted returns p with symlinks resolved, so that the caller runs the
// file that was checked.
func trusted(p string) (string, error) {
	p, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	for d := p; ; d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil {
			return "", err
		}
		if d == p && !fi.Mode().IsRegular() {
			return "", fmt.Errorf("%s is not a regular file", p)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("%s is not owned by root or is writable by others", d)
		}
		if filepath.Dir(d) == d {
			return p, nil
		}
	}
}
