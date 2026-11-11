package sshconn

import (
	"os"
	"strings"

	"golang.org/x/crypto/ssh/knownhosts"
)

// Known reports whether known_hosts has a key for addr (host:port).
func Known(file, addr string) bool {
	b, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	want := knownhosts.Normalize(addr)
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		for _, h := range strings.Split(f[0], ",") {
			if h == want {
				return true
			}
		}
	}
	return false
}
