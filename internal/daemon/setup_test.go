package daemon

import (
	"errors"
	"github.com/ASromancer/ostiary/internal/vault"
	"github.com/zalando/go-keyring"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ASromancer/ostiary/internal/humanok"
	"github.com/ASromancer/ostiary/internal/paths"
)

// setupEmpty is setup without vault, hosts and ssh server: a fresh install.
func setupEmpty(t *testing.T) *harness {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp) // InitVault imports ~/.ssh/config
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "cfg"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(tmp, "state"))
	sockBase := "/tmp"
	if runtime.GOOS == "windows" {
		sockBase = ""
	}
	sockDir, _ := os.MkdirTemp(sockBase, "ostiary-test")
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	t.Setenv("OSTIARY_SOCKET", filepath.Join(sockDir, "s"))

	h := &harness{t: t, tmp: tmp}
	d, err := New(h.notify, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	h.d = d
	h.useHuman(&humanok.Fake{Err: humanok.ErrUnavailable})
	ln, err := net.Listen("unix", paths.Socket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go d.ServeListener(ln)
	if h.c, err = Dial(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.c.Close() })
	return h
}

func TestSetupInitPassphrase(t *testing.T) {
	h := setupEmpty(t)
	var sr SetupReply
	if err := h.call("Setup", &Empty{}, &sr); err != nil || sr.VaultReady {
		t.Fatalf("before init: %v %+v", err, sr)
	}
	var br BeginReply
	if err := h.call("Begin", &BeginArgs{Op: "init", Name: "passphrase"}, &br); err != nil {
		t.Fatal(err)
	}
	var ar AdminReply
	short := AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: "init", Name: "passphrase", Pass: []byte("short")}
	if err := h.call("Admin", &short, &ar); err == nil {
		t.Fatal("short passphrase accepted")
	}
	h.call("Begin", &BeginArgs{Op: "init", Name: "passphrase"}, &br)
	ok := AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: "init", Name: "passphrase", Pass: []byte("long enough pw")}
	if err := h.call("Admin", &ok, &ar); err != nil {
		t.Fatal(err)
	}
	if err := h.call("Setup", &Empty{}, &sr); err != nil || !sr.VaultReady || sr.Locked || sr.Keys != 0 {
		t.Fatalf("after init: %v %+v", err, sr)
	}
	if err := h.call("Begin", &BeginArgs{Op: "init", Name: "keyring"}, &br); err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("second init: %v", err)
	}
	if b, _ := os.ReadFile(paths.Audit()); strings.Contains(string(b), "long enough") {
		t.Fatal("passphrase in audit log")
	}
}

func TestSetupHooksAutostartSkip(t *testing.T) {
	h := setupEmpty(t)
	var installed []string
	auto := false
	h.d.SetSetup(SetupFuncs{
		Agents: func() []AgentState {
			return []AgentState{{Name: "claude", Detected: true, Installed: slices.Contains(installed, "claude")}}
		},
		InstallHook:  func(a string) error { installed = append(installed, a); return nil },
		Autostart:    func() bool { return auto },
		SetAutostart: func(on bool) error { auto = on; return nil },
	})
	var br BeginReply
	var ar AdminReply
	if err := h.call("Begin", &BeginArgs{Op: "hooks", Name: "nope"}, &br); err == nil {
		t.Fatal("unknown agent accepted")
	}
	h.call("Begin", &BeginArgs{Op: "hooks", Name: "claude"}, &br)
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: "hooks", Name: "claude"}, &ar); err != nil || len(installed) != 1 {
		t.Fatalf("hooks: %v %v", err, installed)
	}
	h.call("Begin", &BeginArgs{Op: "autostart", Name: "on"}, &br)
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: "autostart", Name: "on"}, &ar); err != nil || !auto {
		t.Fatalf("autostart: %v %v", err, auto)
	}
	if err := h.call("Begin", &BeginArgs{Op: "autostart", Name: "maybe"}, &br); err == nil {
		t.Fatal("bad autostart value accepted")
	}
	var sr SetupReply
	h.call("SetupSkip", &SetupSkipArgs{Skip: true}, &Empty{})
	if err := h.call("Setup", &Empty{}, &sr); err != nil || !sr.Skipped || !sr.Autostart || !sr.Agents[0].Installed {
		t.Fatalf("setup: %v %+v", err, sr)
	}
}

func TestInitVaultConcurrent(t *testing.T) {
	setupEmpty(t)
	keys := [2]*[32]byte{vault.NewKey(), vault.NewKey()}
	errs := make(chan error, 2)
	for i := range keys {
		go func() { errs <- InitVault(keys[i], nil) }()
	}
	e1, e2 := <-errs, <-errs
	if (e1 == nil) == (e2 == nil) {
		t.Fatalf("want exactly one winner: %v %v", e1, e2)
	}
	opens := 0
	for _, k := range keys {
		if _, err := vault.Open(paths.Vault(), k); err == nil {
			opens++
		}
	}
	if opens != 1 {
		t.Fatalf("vault opens with %d keys", opens)
	}
}

func TestInitKeyring(t *testing.T) {
	keyring.MockInit()
	h := setupEmpty(t)
	var br BeginReply
	var ar AdminReply
	h.call("Begin", &BeginArgs{Op: "init", Name: "keyring"}, &br)
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: "init", Name: "keyring"}, &ar); err != nil {
		t.Fatal(err)
	}
	k1, err := vault.KeyringGet()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Open(paths.Vault(), k1); err != nil {
		t.Fatalf("vault does not open with the keyring key: %v", err)
	}
	// A second init must leave the keyring key alone.
	if err := InitVaultKeyring(vault.NewKey()); !errors.Is(err, ErrInitialized) {
		t.Fatalf("second init: %v", err)
	}
	if k2, _ := vault.KeyringGet(); *k2 != *k1 {
		t.Fatal("existing vault's keyring key was replaced")
	}
}

func TestInitKeyringFailureRemovesVault(t *testing.T) {
	keyring.MockInitWithError(errors.New("no keyring"))
	t.Cleanup(keyring.MockInit)
	setupEmpty(t)
	if err := InitVaultKeyring(vault.NewKey()); err == nil {
		t.Fatal("want keyring error")
	}
	if _, err := os.Stat(paths.Vault()); err == nil {
		t.Fatal("vault left behind after keyring failure")
	}
}
