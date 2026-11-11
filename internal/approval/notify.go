//go:build !e2efake

package approval

// Notify tells the human about a request or an admin code.
func Notify(title, body string) error { return Desktop(title, body) }
