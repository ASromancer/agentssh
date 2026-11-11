// Package paths resolves agentssh's config, state and socket locations.
package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func home() string {
	h, _ := os.UserHomeDir()
	return h
}

// dir honours the XDG variable when set; otherwise uses the platform default.
func dir(env, unixFallback, windowsEnv string) string {
	if d := os.Getenv(env); d != "" {
		return filepath.Join(d, "agentssh")
	}
	if runtime.GOOS == "windows" {
		if d := os.Getenv(windowsEnv); d != "" {
			return filepath.Join(d, "agentssh")
		}
	}
	return filepath.Join(home(), unixFallback, "agentssh")
}

// Config is ~/.config/agentssh (%APPDATA%\agentssh on Windows).
func Config() string { return dir("XDG_CONFIG_HOME", ".config", "APPDATA") }

// State is ~/.local/state/agentssh (%LOCALAPPDATA%\agentssh on Windows).
func State() string      { return dir("XDG_STATE_HOME", filepath.Join(".local", "state"), "LOCALAPPDATA") }
func Hosts() string      { return filepath.Join(Config(), "hosts.toml") }
func Rules() string      { return filepath.Join(Config(), "rules.toml") }
func Vault() string      { return filepath.Join(Config(), "vault.bin") }
func KnownHosts() string { return filepath.Join(Config(), "known_hosts") }
func Audit() string      { return filepath.Join(State(), "audit.jsonl") }
func Out() string        { return filepath.Join(State(), "out") }

func Socket() string {
	if s := os.Getenv("AGENTSSH_SOCKET"); s != "" {
		return s
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home(), "Library", "Application Support", "agentssh", "agentssh.sock")
	case "windows":
		return filepath.Join(State(), "agentssh.sock")
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "agentssh.sock")
	}
	return filepath.Join(State(), "agentssh.sock")
}

// Within reports whether p is dir or inside it (case-insensitive on Windows
// and macOS, whose default file systems are).
func Within(p, dir string) bool {
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	if runtime.GOOS != "linux" {
		p, dir = strings.ToLower(p), strings.ToLower(dir)
	}
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}
