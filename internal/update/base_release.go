//go:build !e2efake

package update

// Base is the release API base; "" means the real GitHub API. Release builds cannot change it.
func Base() string { return "" }
