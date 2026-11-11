# Ostiary P2: onboarding and UX audit. Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A first-time user can go from "vault missing" to "agents connected" entirely in the web UI. The whole UI then gets a UX audit, and its Critical and Important findings are fixed.

**Architecture:** Three new admin operations reuse the existing Begin/Admin approval flow (OS dialog or code): `init` creates the vault, `hooks` installs one agent integration, and `autostart` turns start-at-login on or off. A new `Setup` RPC reports the state of each onboarding step. The agent and service helpers live in package `cli`, and the daemon must not import `cli`, so `cmdDaemon` injects them into the daemon through `SetSetup`, the same pattern as `SetUI`. The UI adds a "Bắt đầu" view driven by `/api/setup`.

**Tech Stack:** Go 1.26 stdlib and existing deps. Vanilla JS/CSS (no build).

**Spec:** `docs/superpowers/specs/2026-11-11-ostiary-release-design.md` (§4)

## Global Constraints

- Every new state-changing operation goes through `Begin` → `Admin` with a ticket and OS authentication or a code. There is no new mutation endpoint that bypasses it.
- UI constraints:
  - CSP `default-src 'self'`.
  - No `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `document.write`.
  - No inline script, style or event-handler attributes.
  - Text that comes from an agent, the filesystem or the daemon is set only via `textContent`.
  - Static files are served only from the explicit files map.
  - UI text is in Vietnamese.
- The daemon package must not import package `cli`. Inject behaviour from the `cli` package with `SetSetup`.
- A vault passphrase must be at least 8 characters, the same rule as `ostiary init`.
- No new dependencies. Do not edit `docs/`. Commit as ASromancer. Each commit message ends with a blank line and then `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Do not push.
- Go toolchain: `export PATH=$HOME/.local/sdk/go/bin:$PATH`. Every task must pass `gofmt -l .` (empty output), `go vet ./...` for linux, darwin and windows, `go vet -tags e2efake ./...`, `go test -race ./...`, `node --check internal/ui/static/app.js`, `node internal/ui/testdata/highlight_test.mjs`, and e2e (`go build -tags e2efake -o /tmp/ostiary-e2e-bin . && python3 scripts/e2e.py /tmp/ostiary-e2e-bin`, 70 checks).
- Tests and demos use temp `XDG_*` directories. Never touch the user's real config, state or running daemon. A Claude Code hook on this machine may block some shell commands; if that happens, rephrase the command. Never disable the hook.

---

### Task 1: Daemon and CLI plumbing: init/hooks/autostart ops, Setup RPC, uninstall-service

**Files:**
- Modify: `internal/daemon/rpc.go` (new types, `AdminArgs.Pass`)
- Create: `internal/daemon/setup.go` (`SetupFuncs`, `SetSetup`, `InitVault`, `Setup` and `SetupSkip` RPCs, the setup state file)
- Modify: `internal/daemon/admin.go` (ops `init`, `hooks`, `autostart` in `Begin`, `Admin` and `adminMessage`)
- Modify: `internal/paths/paths.go` (`SetupState()`)
- Modify: `internal/cli/human.go` (`cmdInit` uses `daemon.InitVault`, `cmdDaemon` calls `SetSetup`, new `cmdUninstallService`)
- Modify: `internal/cli/cli.go` (register `uninstall-service`, usage line)
- Modify: `internal/cli/install.go` (`hookInstalled`, `agentStates`)
- Modify: `internal/cli/os_unix.go`, `internal/cli/os_windows.go` (`installService(startNow bool)`, `removeService()`, `serviceInstalled() bool`)
- Modify: `internal/ui/backend.go`, `internal/ui/api.go`, `internal/ui/fake_test.go` (`/api/setup`, `/api/setup/skip`, `pass` in admin commit)
- Test: `internal/daemon/setup_test.go`, `internal/cli/install_test.go`, `internal/ui/api_test.go`

**Interfaces:**
- Produces, in package `daemon`:

```go
type AgentState struct {
	Name      string // claude | codex | gemini | antigravity
	Detected  bool   // the agent's config dir exists
	Installed bool   // our hook/plugin is configured
}

type SetupFuncs struct {
	Agents       func() []AgentState
	InstallHook  func(agent string) error
	Autostart    func() bool
	SetAutostart func(on bool) error
}

type SetupReply struct {
	VaultReady    bool // vault file exists
	Locked        bool
	Hosts         int
	Keys          int // keys + passwords; -1 while locked
	Agents        []AgentState
	Autostart     bool
	PolkitMissing bool // linux only: the polkit policy file is absent
	Skipped       bool // the user hid the guide
}

type SetupSkipArgs struct{ Skip bool }

func (d *Daemon) SetSetup(f SetupFuncs)
func InitVault(key *[32]byte, salt []byte) error // dirs, hosts.toml (imported from ~/.ssh/config if absent), empty vault
func (s *Service) Setup(_ *Empty, r *SetupReply) error
func (s *Service) SetupSkip(a *SetupSkipArgs, _ *Empty) error
```

- `AdminArgs` gains `Pass []byte`, the vault passphrase for `init`.
- Admin ops:
  - `init` with Name `keyring` or `passphrase`. `Begin` errors with `already initialized` if the vault exists. For Name `passphrase`, `Admin` requires `len(Pass) >= 8`.
  - `hooks` with Name equal to one of `SetupFuncs.Agents()` names.
  - `autostart` with Name `on` or `off`.
- UI: `GET /api/setup` returns `SetupReply` as JSON. `POST /api/setup/skip` takes `{"skip":bool}`. `POST /api/admin/commit` accepts `"pass"`.
- CLI: `ostiary uninstall-service` (human only, needs a TTY like `install-service`).

- [ ] **Step 1: Write the failing daemon test**

`internal/daemon/setup_test.go`. Model it on `setup(t)` in `daemon_test.go`, but start from a missing vault: temp `XDG_*` dirs and a socket, no vault, no hosts file. The harness's code-mode notifier delivers codes the same way, and `h.lastCode()` reads them back. Add a helper `setupEmpty(t)` that copies `setup` minus the vault, hosts and ssh server. If extracting a shared part of `setup` is cleaner, do that.

```go
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
```

Run: `go test ./internal/daemon/ -run TestSetup`. Expected: compile failure, because the types are undefined.

- [ ] **Step 2: Implement `internal/daemon/setup.go` and the admin ops**

`setup.go`:

```go
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
```

Edits elsewhere:
- Add field `setup SetupFuncs` to `Daemon`.
- Add `func SetupState() string { return filepath.Join(State(), "setup.json") }` to `paths.go`, following the style of its neighbours.
- If `d.snapshot()` returns a nil config while the vault is missing, guard as shown.

`admin.go`:
1. Add `"init": true, "hooks": true, "autostart": true` to `adminOps`.
2. In `Begin`, after the op check and before creating the ticket, validate:

```go
	switch a.Op {
	case "init":
		if _, err := os.Stat(paths.Vault()); err == nil {
			return errors.New("already initialized")
		}
		if a.Name != "keyring" && a.Name != "passphrase" {
			return fmt.Errorf("init mode must be keyring or passphrase, not %q", a.Name)
		}
	case "autostart":
		if a.Name != "on" && a.Name != "off" {
			return fmt.Errorf("autostart must be on or off, not %q", a.Name)
		}
	case "hooks":
		known := false
		if s.d.setup.Agents != nil {
			for _, ag := range s.d.setup.Agents() {
				known = known || ag.Name == a.Name
			}
		}
		if !known {
			return fmt.Errorf("unknown agent %q", a.Name)
		}
	}
```

3. In `d.admin`, before the `d.mu.Lock()` / vault-locked check (next to `trust`), handle the three ops and `return` early, because they do not need an unlocked vault:

```go
	switch a.Op {
	case "init":
		key, salt := vault.NewKey(), []byte(nil)
		if a.Name == "passphrase" {
			if len(a.Pass) < 8 {
				return errors.New("use at least 8 characters for the passphrase")
			}
			salt = vault.NewSalt()
			key = vault.DeriveKey(a.Pass, salt)
		} else if err := vault.KeyringSet(key); err != nil {
			return fmt.Errorf("OS keyring unavailable (%v); choose a passphrase instead", err)
		}
		if err := InitVault(key, salt); err != nil {
			return err
		}
		if err := d.loadConfig(); err != nil {
			return err
		}
		if err := d.unlock(key, salt); err != nil {
			return err
		}
		r.Out = "vault created: " + paths.Vault()
		return nil
	case "hooks":
		if d.setup.InstallHook == nil {
			return errors.New("agent setup is not available in this daemon")
		}
		if err := d.setup.InstallHook(a.Name); err != nil {
			return err
		}
		r.Out = "installed the Ostiary hook for " + a.Name
		return nil
	case "autostart":
		if d.setup.SetAutostart == nil {
			return errors.New("autostart is not available in this daemon")
		}
		if err := d.setup.SetAutostart(a.Name == "on"); err != nil {
			return err
		}
		r.Out = map[string]string{"on": "Ostiary will start at login", "off": "Ostiary will no longer start at login"}[a.Name]
		return nil
	}
```

Check what `vault.NewKey` and `vault.DeriveKey` return, and match them; `cmdInit` shows the correct calls. Clear `a.Pass` after use with `clear(a.Pass)`.

4. Add these cases to `adminMessage`, so the OS dialog states exactly what will happen:

```go
	case "init":
		return "create the Ostiary vault (" + a.Name + ")"
	case "hooks":
		return "install the Ostiary hook and skill for " + a.Name
	case "autostart":
		if a.Name == "on" {
			return "start Ostiary automatically at login"
		}
		return "stop starting Ostiary at login"
```

5. The audit entry `Cmd` for these ops must never contain the passphrase. `Cmd` is built from Op and Name only, which already holds; keep it that way.

Refactor `cmdInit` in `human.go` to call `daemon.InitVault(key, salt)` and drop its own directory, hosts.toml and vault.Save code. Keep its TTY prompts and messages, including the "imported N hosts" line. `InitVault` does not report the count, so print "imported hosts from ~/.ssh/config" only when `hosts.toml` did not exist before the call.

Run: `go test ./internal/daemon/ -run TestSetup`. Expected: PASS.

- [ ] **Step 3: CLI helpers (test first)**

Add to `internal/cli/install_test.go`, using the existing temp-HOME pattern in that file:

```go
func TestAgentStates(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	var claude daemon.AgentState
	for _, s := range agentStatesIn(home) {
		if s.Name == "claude" {
			claude = s
		}
	}
	if !claude.Detected || claude.Installed {
		t.Fatalf("before: %+v", claude)
	}
	if err := installClaude(home, `"/x/ostiary" hook claude`); err != nil {
		t.Fatal(err)
	}
	for _, s := range agentStatesIn(home) {
		if s.Name == "claude" && !s.Installed {
			t.Fatal("installed hook not detected")
		}
	}
}
```

Implement in `install.go`:

```go
// hookInstalled reports whether an Ostiary hook (or the Claude plugin) is
// configured for agent under home.
func hookInstalled(agent, home string) bool {
	b, err := os.ReadFile(hookFile(agent, home))
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, " hook "+agent) && strings.Contains(s, "ostiary") ||
		agent == "claude" && strings.Contains(s, `"ostiary@`)
}

func agentStatesIn(home string) []daemon.AgentState {
	out := make([]daemon.AgentState, 0, len(installers))
	for _, in := range installers {
		out = append(out, daemon.AgentState{Name: in.name, Detected: in.detect(home), Installed: hookInstalled(in.name, home)})
	}
	return out
}

func installHookFor(agent string) error {
	home, _ := os.UserHomeDir()
	for _, in := range installers {
		if in.name == agent {
			cmd, err := hookCommand(agent)
			if err != nil {
				return err
			}
			return in.install(home, cmd)
		}
	}
	return fmt.Errorf("unknown agent %q", agent)
}
```

Before relying on `hookFile`, open `install.go` and check that it points at the file each installer actually writes (Codex `hooks.json`, Antigravity `config/hooks.json`). If an installer writes the hook elsewhere, use that path.

Service helpers, in `os_unix.go` and `os_windows.go`:
- `installService(startNow bool) error`. `startNow=true` keeps today's behaviour for `ostiary install-service`. With `startNow=false` (UI autostart):
  - Linux: write the unit, then run `daemon-reload` and `enable` without `--now` and without the import-environment/restart steps.
  - macOS: write the plist only, without `launchctl load`. It loads at next login.
  - Windows: create the schtasks task only, without `startDetached`.

  Reason: the daemon serving the UI is already running, and starting a second one would fight it for the socket.
- `removeService() error`. Linux: `systemctl --user disable ostiary.service` (ignore an "not loaded" error), remove the unit file, `daemon-reload`. macOS: remove the plist file. Windows: `schtasks /Delete /F /TN ostiary`. Never stop the running daemon.
- `serviceInstalled() bool`. Linux: the unit file exists and `systemctl --user is-enabled ostiary.service` succeeds. macOS: the plist file exists. Windows: `schtasks /Query /TN ostiary` succeeds.

Update existing callers: `cmdInstallService` and `cmdInit` call `installService(true)`.

New `cmdUninstallService` (registered as `uninstall-service`, with a usage line next to `install-service`):

```go
func cmdUninstallService(args []string) int {
	if t, code := openTTY("uninstall-service"); t == nil {
		return code
	}
	if err := removeService(); err != nil {
		return errf(1, "%v", err)
	}
	fmt.Println("Ostiary will no longer start at login (the running daemon was left alone)")
	return 0
}
```

The P3 Windows uninstaller will call this without a console. `openTTY` fails there, so also accept `--yes` to skip the TTY requirement. Agents still cannot use it, because `uninstall-service` is human-only in the hook.

In `cmdDaemon`, right after `daemon.New`:

```go
	d.SetSetup(daemon.SetupFuncs{
		Agents: func() []daemon.AgentState {
			home, _ := os.UserHomeDir()
			return agentStatesIn(home)
		},
		InstallHook:  installHookFor,
		Autostart:    serviceInstalled,
		SetAutostart: func(on bool) error {
			if on {
				return installService(false)
			}
			return removeService()
		},
	})
```

Run: `go test ./internal/cli/ ./internal/daemon/`. Expected: PASS.

- [ ] **Step 4: UI backend and API (test first)**

- `Backend` interface gains `Setup() (daemon.SetupReply, error)` and `SetupSkip(skip bool) error`. Implement both in `ServiceBackend` and in `fakeBackend`. The fake returns a stored `SetupReply` and records skip.
- `api.go`:
  - `GET /api/setup` writes `SetupReply`.
  - `POST /api/setup/skip` reads `{"skip":bool}` through `readJSON` (which keeps the JSON content-type and Origin guard) and replies `{}`.
  - In `POST /api/admin/commit`, add `Pass string` to the request struct and pass `[]byte(a.Pass)` as `AdminArgs.Pass` when non-empty.
- In `api_test.go`, follow the existing handler-test style:
  - `/api/setup` returns the fake's reply as JSON;
  - `/api/setup/skip` with `{"skip":true}` reaches the fake;
  - a commit with `"pass":"x"` reaches `AdminArgs.Pass`; extend the fake's `Admin` to record its last args if it doesn't already.

Run: `go test ./internal/ui/`. Expected: PASS.

- [ ] **Step 5: Full verification and commit**

Run the full check list from Global Constraints. Then commit:

```bash
git add -A
git commit -m "feat: init, agent hooks and autostart as approved admin ops; Setup RPC; uninstall-service

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: "Bắt đầu" onboarding view

**Files:**
- Modify: `internal/ui/static/index.html` (new `<section class="view" data-view="setup">`, a sidebar footer link, a top-bar chip)
- Modify: `internal/ui/static/app.js` (setup view, auto-show, key actions extracted to functions)
- Modify: `internal/ui/static/app.css` (step list styles)
- Modify: `internal/ui/static_test.go` (views list includes `setup`; JS calls `/api/setup` and `/api/setup/skip`)

**Interfaces:**
- Consumes:
  - `GET /api/setup` returns `SetupReply` (JSON field names are the Go field names: `VaultReady`, `Locked`, `Hosts`, `Keys`, `Agents[{Name,Detected,Installed}]`, `Autostart`, `PolkitMissing`, `Skipped`).
  - `POST /api/setup/skip {skip}`.
  - The admin ops `init` (Name `keyring`/`passphrase`, extra `{pass}`), `hooks` (Name = agent) and `autostart` (Name `on`/`off`) go through the existing JS `admin(op, name, extra)`.
- Produces: `VIEWS.setup = "Bắt đầu"`; deep link `#setup`.

- [ ] **Step 1: Static test first**

In `internal/ui/static_test.go`:
- add `setup` to the required `data-view` values;
- add `/api/setup` and `/api/setup/skip` to the endpoints the JS must reference.

Run `go test ./internal/ui/ -run Static`, which should fail.

- [ ] **Step 2: Extract the key actions**

In `app.js`, move the three click handlers of `#keygen`, `#keyimport` and `#pwimport` into named functions `genKey()`, `importKey()` and `savePassword()`. Each returns a promise that resolves after success or cancel. The buttons keep calling them. Behaviour does not change.

- [ ] **Step 3: The view**

`index.html`:
- Add `<section class="view" data-view="setup" aria-labelledby="title"><div id="setupbox"></div></section>` among the other views.
- In `.side-foot`, before the connection dot, add `<button type="button" id="opensetup" class="linkbtn">Hướng dẫn bắt đầu</button>`.
- In the top bar, add `<button type="button" id="setupchip" class="chip hidden"></button>`. When steps remain, its text is "Thiết lập 2/5"; clicking it goes to `#setup`.

`app.js`:
- Add `setup: "Bắt đầu"` to `VIEWS`.
- `showView` must handle a view that is not in the nav, so no nav button is highlighted.
- Implement `loadSetup()`, which renders `#setupbox` from `/api/setup` as an ordered list of step cards.

Each step card has:
- a status icon: a `check` icon in `--ok` when done, otherwise the step number in a circle;
- a title and a one-line explanation;
- the action controls listed below;
- a muted "Xong" label when done.

| # | Title | Done when | Controls |
|---|---|---|---|
| 1 | Tạo vault | `VaultReady` | If not ready: primary "Tạo vault" (`admin("init","keyring")`) plus a link-button "Dùng passphrase thay vì keyring". The link-button opens `askForm` with two password fields, "Passphrase" and "Nhập lại". Validate: ≥ 8 characters and both equal, with the error shown in the field. On success, call `admin("init","passphrase",{pass})`. If ready but `Locked`: show "Mở khóa", reusing the vault toggle. |
| 2 | Thêm host | `Hosts > 0` | "Thêm host" calls `openHostDrawer()`. After the drawer closes, reload setup. When done, add the hint "Nhớ bấm Trust host key cho host mới ở màn Host." |
| 3 | Thêm key hoặc mật khẩu | `Keys > 0` | "Tạo key" calls `genKey()`, "Import key" calls `importKey()`, "Lưu mật khẩu" calls `savePassword()`. Disabled with a hint while `Locked` or `!VaultReady`. |
| 4 | Kết nối AI agent | at least one agent with `Installed` | One row per agent: display name (claude → "Claude Code", codex → "Codex", gemini → "Gemini CLI", antigravity → "Antigravity"), then a pill "Đã cài" (ok) / "Chưa cài" / "Không thấy trên máy" (muted, when `!Detected`), then a button "Cài" (`admin("hooks", name)`) when detected and not installed. |
| 5 | Tự chạy khi đăng nhập | `Autostart` | A toggle switch (a checkbox with `role="switch"`, styled like the host drawer's agent toggle). On change, call `admin("autostart", on ? "on" : "off")`. If it fails, revert the switch. |
| 6 (Linux, only when `PolkitMissing`) | Duyệt bằng mật khẩu máy | never auto-done; the card is optional | Text: "Để duyệt bằng hộp thoại mật khẩu của hệ điều hành thay vì mã, chạy một lần trong terminal:" followed by a code block `sudo "$(command -v ostiary)" install-polkit` with `copyBtn`. Then: "rồi khởi động lại Ostiary." |

- Footer: "Ẩn hướng dẫn" (`POST /api/setup/skip {skip:true}`, then `location.hash = "#approvals"`). When steps 1–5 are all done, show a success panel instead: "Xong! Agent giờ dùng được các host bạn bật 'agent'." with a button "Về màn Duyệt".
- Auto-show: in the first `refresh()` after page load, fetch `/api/setup`. If `!VaultReady`, or if `!Skipped` and any of steps 1–5 is not done, and the URL hash is empty, set `location.hash = "#setup"`. Also update `#setupchip`: visible when steps remain, text `"Thiết lập " + done + "/5"`. A `#req=N` deep link always wins over auto-show.
- After every successful action, run `loadSetup()` and `refresh()`. Errors go through `fail()`.
- `#opensetup` sets `location.hash = "#setup"`, and also clears `Skipped` (`POST /api/setup/skip {skip:false}`) so the chip comes back.

CSS: a `.steps` list with 12px gaps. Each `.step` is a card with a grid of 32px icon column plus content. `.step.done` uses muted text. Steps stack on screens narrower than 640px. Touch targets ≥ 40px.

- [ ] **Step 4: Verify**

Run `go test ./internal/ui/` (it should pass) and then the full check list.

Take screenshots of the setup view at 1440×900 in light and dark and at 390×844, in two states:
- (a) nothing done (`VaultReady:false`);
- (b) vault and host done, agents partly installed.

Use a temporary demo test with `fakeBackend` returning those `SetupReply` values; never commit it. Look at each screenshot. Save them as `/tmp/shots/setup-*.png`.

- [ ] **Step 5: Commit**

```bash
git add internal/ui
git commit -m "feat(ui): Bắt đầu onboarding view (vault, host, key, agents, autostart, polkit hint)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: UX audit (review only, no code)

**Files:**
- Create: `.superpowers/sdd/2026-11-11-ostiary-p2-onboarding-ux/ux-audit.md`

This task is run by a reviewer, not an implementer. The reviewer reads `internal/ui/static/*` and the API, runs the UI with a fake backend, and takes screenshots of every view in both themes at 1440, 760 and 390 widths. They write findings to the file above, each with: severity (Critical / Important / Minor), view, what is wrong, a concrete user scenario, and a suggested fix.

Checklist to cover:
- Nielsen's heuristics;
- empty, loading and error states on every view;
- Vietnamese copy consistency (English only for host key / fingerprint / known hosts / agent);
- keyboard and focus order;
- confirmations before destructive actions;
- shortest paths for: approve a request, add a host, trust a host, add a key, view an output;
- contrast in both themes;
- the new Bắt đầu view.

The reviewer must also list daemon error strings the UI shows raw (grep the `errors.New` and `fmt.Errorf` messages reachable from `/api/*`). Mark the ones a user will commonly hit.

---

### Task 4: Fix audit findings and translate common errors

**Files:**
- Modify: `internal/ui/static/app.js`, `app.css`, `index.html` as the findings require
- Test: `internal/ui/testdata/errors_test.mjs` (new), CI step next to the highlight test in `.github/workflows/ci.yml`

**Interfaces:**
- Produces: `export function friendlyError(msg)` in `app.js`, exported the same way as `byteToJs` for the Node test.

- [ ] **Step 1: Error translation (test first)**

`internal/ui/testdata/errors_test.mjs` should import `friendlyError` the same way `highlight_test.mjs` imports `byteToJs`, and assert:

```js
const cases = [
  ["approval ticket expired or invalid; start again", "Phiếu duyệt đã hết hạn. Hãy thao tác lại."],
  ["wrong code: 2 tries left", "Sai mã duyệt (còn 2 lần thử)."],
  ["vault is locked; run 'ostiary unlock' first", "Vault đang khóa. Mở khóa ở chip Vault trên cùng rồi thử lại."],
  ["dial tcp 10.0.0.5:22: connect: connection refused", "Không kết nối được host (connection refused)."],
  ["dial tcp 10.0.0.5:22: i/o timeout", "Không kết nối được host (hết thời gian chờ)."],
  ["hosts.toml or rules.toml changed on disk; review the change and run 'ostiary reload' first", "Cấu hình trên đĩa đã đổi. Kiểm tra rồi bấm \"Đọc lại cấu hình\" ở màn Host."],
  ["authentication cancelled", "Bạn đã hủy xác thực."],
  ["something else entirely", "something else entirely"],
];
```

Before writing these cases, check the exact wording of the cancel and wrong-code errors in `internal/approval` and `internal/humanok`, and match the test to the real strings. Have `fail()` pass messages through `friendlyError`. Add the Node test to CI right after `node internal/ui/testdata/highlight_test.mjs`.

- [ ] **Step 2: Fix every Critical and Important finding from `ux-audit.md`**

Fix each one with the smallest change, and note in the report which finding each change addresses. Minor findings: fix the cheap ones and list the rest in the report.

- [ ] **Step 3: Verify and commit**

Run the full check list. Retake the screenshots of the views you changed and look at them.

```bash
git add -A
git commit -m "fix(ui): UX audit fixes and Vietnamese messages for common errors

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
