package vault

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// lockMemory keeps b out of the page file when the working set allows it.
func lockMemory(b []byte) {
	if len(b) > 0 {
		_ = windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	}
}
