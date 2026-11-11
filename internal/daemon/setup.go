package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"

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
	if _, err := os.Stat(paths.Vault()); err == nil {
		return errors.New("already initialized")
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
	return vault.Save(paths.Vault(), key, salt, &vault.Data{ConfigHash: ConfigHash()})
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
	if d.setup.Autostart != nil {
		r.Autostart = d.setup.Autostart()
	}
	if runtime.GOOS == "linux" {
		_, err := os.Stat(humanok.PolicyPath)
		r.PolkitMissing = err != nil
	}
	r.Skipped = readSetupState().Skipped
	return nil
}

func (s *Service) SetupSkip(a *SetupSkipArgs, _ *Empty) error {
	if err := os.MkdirAll(paths.State(), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(setupState{Skipped: a.Skip})
	return os.WriteFile(paths.SetupState(), b, 0o600)
}
