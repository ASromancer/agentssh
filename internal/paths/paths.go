// Package paths resolves agentssh's config, state and socket locations.
package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

func home() string {
	h, _ := os.UserHomeDir()
	return h
}

func xdg(env, fallback string) string {
	if d := os.Getenv(env); d != "" {
		return filepath.Join(d, "agentssh")
	}
	return filepath.Join(home(), fallback, "agentssh")
}

func Config() string     { return xdg("XDG_CONFIG_HOME", ".config") }
func State() string      { return xdg("XDG_STATE_HOME", ".local/state") }
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
	if runtime.GOOS == "darwin" {
		return filepath.Join(home(), "Library", "Application Support", "agentssh", "agentssh.sock")
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "agentssh.sock")
	}
	return filepath.Join(State(), "agentssh.sock")
}
