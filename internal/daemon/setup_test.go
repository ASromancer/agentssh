package daemon

import (
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
