//go:build e2efake

package update

import "os"

// Base lets the e2e test point the release lookup at a local server. Test builds only.
func Base() string { return os.Getenv("OSTIARY_E2E_RELEASES_URL") }
