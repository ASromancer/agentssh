package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ASromancer/ostiary/internal/hosts"
	"github.com/ASromancer/ostiary/internal/humanok"
	"github.com/ASromancer/ostiary/internal/paths"
	"github.com/ASromancer/ostiary/internal/vault"
)

// SetSetup installs the agent/service helpers that live in package cli.
// Call it before Serve. Without it, Setup reports no agents and the hooks
// and autostart ops fail.
func (d *Daemon) SetSetup(f SetupFuncs) { d.setup = f }

// InitVault creates the config/state dirs, a hosts.toml (importing
// ~/.ssh/config hosts, hidden from agents) when there is none, and an
// empty vault sealed with key (and salt in passphrase mode).
func InitVault(key *[32]byte, salt []byte) error {
	initMu.Lock()
	defer initMu.Unlock()
	return initLocked(key, salt)
}

// ErrInitialized means a vault already exists; nothing was changed.
var ErrInitialized = errors.New("already initialized")

var initMu sync.Mutex // serializes vault creation (and the keyring write that follows)

// InitVaultKeyring is InitVault for keyring mode: the vault is created
// first (exclusively), and only then is key stored in the keyring, so an
// existing vault's keyring entry is never replaced. If the keyring write
// fails, the new vault is removed again.
func InitVaultKeyring(key *[32]byte) error {
	initMu.Lock()
	defer initMu.Unlock()
	if err := initLocked(key, nil); err != nil {
		return err
	}
	if err := vault.KeyringSet(key); err != nil {
		os.Remove(paths.Vault())
		return err
	}
	return nil
}

func initLocked(key *[32]byte, salt []byte) error {
	if _, err := os.Stat(paths.Vault()); err == nil {
		return ErrInitialized
	}
	for _, dir := range []string{paths.Config(), paths.State(), paths.Out()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if _, err := os.Stat(paths.Hosts()); errors.Is(err, os.ErrNotExist) {
		cfg := &hosts.Config{Hosts: map[string]*hosts.Host{}}
		home, _ := os.UserHomeDir()
		if imported, err := hosts.ImportSSHConfig(filepath.Join(home, ".ssh", "config")); err == nil {
			cfg.Hosts = imported
		}
		if err := cfg.Save(paths.Hosts()); err != nil {
			return err
		}
	}
	err := vault.Create(paths.Vault(), key, salt, &vault.Data{ConfigHash: ConfigHash()})
	if errors.Is(err, os.ErrExist) {
		return ErrInitialized
	}
	return err
}

type setupState struct {
	Skipped bool `json:"skipped"`
}

func readSetupState() setupState {
	var s setupState
	if b, err := os.ReadFile(paths.SetupState()); err == nil {
		json.Unmarshal(b, &s)
	}
	return s
}

func (s *Service) Setup(_ *Empty, r *SetupReply) error {
	d := s.d
	_, err := os.Stat(paths.Vault())
	r.VaultReady = err == nil
	cfg, _, _, _ := d.snapshot()
	if cfg != nil {
		r.Hosts = len(cfg.Hosts)
	}
	d.mu.Lock()
	r.Locked = d.data == nil
	r.Keys = -1
	if d.data != nil {
		r.Keys = len(d.data.Keys) + len(d.data.Passwords)
	}
	d.mu.Unlock()
	r.Agents = []AgentState{}
	if d.setup.Agents != nil {
		r.Agents = d.setup.Agents()
	}
	r.Autostart = d.autostart()
	if runtime.GOOS == "linux" {
		_, err := os.Stat(humanok.PolicyPath)
		r.PolkitMissing = err != nil
	}
	r.Skipped = readSetupState().Skipped
	r.CLIHint = cliHint(runtime.GOOS, selfExe(), func() bool { _, err := exec.LookPath("ostiary"); return err == nil })
	return nil
}

// cliHint: a macOS .app install has no ostiary on PATH, so agents (skill, MCP, hooks) cannot run it.
func cliHint(goos, exe string, onPath func() bool) string {
	if goos != "darwin" || !strings.Contains(exe, ".app/Contents/MacOS/") || onPath() {
		return ""
	}
	return fmt.Sprintf("sudo ln -sf %q /usr/local/bin/ostiary", exe)
}

func (s *Service) SetupSkip(a *SetupSkipArgs, _ *Empty) error {
	if err := os.MkdirAll(paths.State(), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(setupState{Skipped: a.Skip})
	return os.WriteFile(paths.SetupState(), b, 0o600)
}

// autostart caches setup.Autostart (it runs systemctl) for 30s; the
// autostart op drops the cache.
func (d *Daemon) autostart() bool {
	if d.setup.Autostart == nil {
		return false
	}
	d.autoMu.Lock()
	defer d.autoMu.Unlock()
	if time.Since(d.autoAt) > 30*time.Second {
		d.autoVal, d.autoAt = d.setup.Autostart(), time.Now()
	}
	return d.autoVal
}
