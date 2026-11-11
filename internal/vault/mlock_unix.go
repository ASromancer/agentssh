//go:build linux || darwin

package vault

import "syscall"

// lockMemory keeps b out of swap; RLIMIT_MEMLOCK may forbid it.
func lockMemory(b []byte) { _ = syscall.Mlock(b) }
