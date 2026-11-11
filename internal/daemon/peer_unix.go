//go:build linux || darwin

package daemon

import (
	"fmt"
	"os"
	"syscall"
)

func umask(m int) int { return syscall.Umask(m) }

func samePeerUser(fd uintptr) error {
	uid, err := peerUID(int(fd))
	if err != nil {
		return err
	}
	if uid != os.Getuid() {
		return fmt.Errorf("peer uid %d is not %d", uid, os.Getuid())
	}
	return nil
}
