//go:build !e2efake

package approval

// Notify tells the human about a request or an admin code.
func Notify(n Notice) error { return Desktop(n) }
