# Ostiary P3: desktop apps and installers. Implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clicking an Ostiary icon on any OS starts the daemon if needed and opens the web UI. Every release ships a Windows installer, a macOS `.dmg` and a Linux `.deb`, alongside the plain archives.

**Architecture:** One new CLI verb, `ostiary open`, is the entry point behind every icon. Windows gets a second build of the same code with the GUI subsystem (`ostiary-app.exe`), which runs `open` when started without arguments. macOS gets a `.app` bundle whose executable is a two-line launcher script. Linux gets a `.desktop` entry, written either by `install-service` or by the `.deb`. A `stop` verb and a `Shutdown` RPC let installers replace binaries cleanly. Packaging runs only in CI (nfpm, Inno Setup, `hdiutil`, `lipo`), and every artefact gets a structural smoke check there.

**Tech Stack:** Go 1.26. nfpm (build-time only, installed in CI with `go install` at a pinned version). Inno Setup 6. macOS `lipo`/`hdiutil`. GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-11-ostiary-release-design.md` (§5, §7)

## Global Constraints

- Identifiers and paths:
  - module `github.com/ASromancer/ostiary`;
  - binaries `ostiary` and `ostiary-app.exe` (Windows GUI build);
  - unit `ostiary.service`, launchd label `dev.ostiary`, schtasks task `ostiary`;
  - bundle id `dev.ostiary.app`;
  - icons from `internal/brand` (`brand.PNG(n)`), and ICO/ICNS via `go run ./tools/brandgen -out DIR`.
- `open`, `stop`, `upgrade`, `uninstall-service`, `install-service` and `ui` are human-only. Add `open` and `stop` to the hook's human-only set where missing, and add hook test rows for them.
- No new Go module dependencies. Build-time tools (nfpm, Inno Setup) are installed only in CI. Pin the nfpm version.
- Windows installer: per-user, no admin, installs to `{userpf}\Ostiary` (`%LOCALAPPDATA%\Programs\Ostiary`), and adds the install dir to the user's PATH. The installers are unsigned; the README explains the SmartScreen and Gatekeeper prompts.
- Release binaries must not contain `OSTIARY_E2E`. Keep the existing marker check and run it on every binary, including `ostiary-app.exe` and the universal macOS binary.
- Commit as ASromancer. Each commit message ends with a blank line and then `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Do not push; the controller pushes to run CI.
- Local checks for every task:
  - `gofmt -l .` prints nothing;
  - `go vet ./...` passes for linux, darwin and windows, and for `-tags e2efake`;
  - `go test -race ./...` passes;
  - the node checks pass;
  - e2e passes all 70 checks.
- Never touch the user's real config, state or running daemon. A Claude Code hook on this machine may block some shell commands; rephrase the command and never disable the hook.

---

### Task 1: `ostiary open`, `ostiary stop`, Shutdown RPC, Windows GUI entry

**Files:**
- Create: `internal/cli/open.go`, `internal/cli/open_test.go`
- Modify: `internal/cli/cli.go` (register `open` and `stop`, usage, default action for `ostiary-app.exe`)
- Modify: `internal/daemon/service.go` (`Shutdown` RPC), `internal/daemon/daemon.go` (keep the listener so it can close it), `internal/daemon/daemon_test.go`
- Modify: `internal/cli/os_unix.go`, `internal/cli/os_windows.go` (`startService() error`)
- Modify: `internal/cli/install.go` (`hookCommand` uses the console exe on Windows)
- Modify: `internal/hook/hook.go` and its test (`open` and `stop` are human-only)

**Interfaces:**
- Produces:
  - `func cmdOpen(args []string) int` and `func cmdStop(args []string) int`;
  - `func (s *Service) Shutdown(_ *Empty, _ *Empty) error`, which closes the listener so `Serve` returns and `cmdDaemon` exits 0;
  - `func cliExe() (string, error)`, which returns the console binary path (`ostiary.exe` next to `ostiary-app.exe` on Windows, otherwise `os.Executable()`);
  - `func startService() error`, which starts the installed service now.
- Consumes: `serviceInstalled() bool`, `installService(startNow bool)`, `removeService()` from P2; `dialRetry`; `daemon.Running()`; `approval.OpenURL`; `approval.Notify`.

- [ ] **Step 1: Failing test for the open flow**

`internal/cli/open_test.go` tests a pure helper with the side effects injected:

```go
package cli

import (
	"errors"
	"testing"
)

func TestOpenFlow(t *testing.T) {
	var calls []string
	f := openDeps{
		running:     func() bool { return false },
		installed:   func() bool { return true },
		startSvc:    func() error { calls = append(calls, "svc"); return nil },
		startDetach: func() error { calls = append(calls, "detach"); return nil },
		wait:        func() error { calls = append(calls, "wait"); return nil },
		login:       func() (string, error) { return "http://127.0.0.1:1/?n=x", nil },
		browse:      func(u string) error { calls = append(calls, "open "+u); return nil },
	}
	if err := openFlow(f); err != nil || len(calls) != 3 || calls[0] != "svc" || calls[2] != "open http://127.0.0.1:1/?n=x" {
		t.Fatalf("%v %v", err, calls)
	}
	// service start fails: fall back to a detached daemon
	calls = nil
	f.startSvc = func() error { return errors.New("no systemd") }
	if err := openFlow(f); err != nil || calls[0] != "detach" {
		t.Fatalf("fallback: %v %v", err, calls)
	}
	// already running: no start at all
	calls = nil
	f.running = func() bool { return true }
	if err := openFlow(f); err != nil || calls[0] != "open http://127.0.0.1:1/?n=x" {
		t.Fatalf("running: %v %v", err, calls)
	}
}

func TestAppDefault(t *testing.T) {
	for exe, want := range map[string]bool{
		`C:\Users\a\AppData\Local\Programs\Ostiary\ostiary-app.exe`: true,
		`C:\x\OSTIARY-APP.EXE`:                                      true,
		`C:\x\ostiary.exe`:                                          false,
		"/usr/bin/ostiary":                                          false,
	} {
		if appDefault(exe) != want {
			t.Errorf("%s: want %v", exe, want)
		}
	}
}
```

Run `go test ./internal/cli/ -run 'TestOpenFlow|TestAppDefault'`. It should fail, because the functions don't exist yet.

- [ ] **Step 2: Implement `open.go`**

```go
package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ASromancer/ostiary/internal/approval"
	"github.com/ASromancer/ostiary/internal/daemon"
	"github.com/ASromancer/ostiary/internal/paths"
)

type openDeps struct {
	running             func() bool
	installed           func() bool
	startSvc, startDetach func() error
	wait                func() error
	login               func() (string, error)
	browse              func(string) error
}

// openFlow starts the daemon when needed (service first, detached daemon as
// fallback), waits for its socket, and opens a one-time UI login link.
func openFlow(f openDeps) error {
	if !f.running() {
		started := false
		if f.installed() {
			started = f.startSvc() == nil
		}
		if !started {
			if err := f.startDetach(); err != nil {
				return fmt.Errorf("start the daemon: %w", err)
			}
		}
		if err := f.wait(); err != nil {
			return errors.New("the daemon did not start; see " + filepath.Join(paths.State(), "daemon.log"))
		}
	}
	u, err := f.login()
	if err != nil {
		return err
	}
	return f.browse(u)
}

// appDefault: the Windows GUI build runs "open" when started with no arguments.
func appDefault(exe string) bool {
	return strings.EqualFold(filepath.Base(strings.ReplaceAll(exe, `\`, "/")), "ostiary-app.exe")
}

func cmdOpen(args []string) int {
	err := openFlow(openDeps{
		running:     daemon.Running,
		installed:   serviceInstalled,
		startSvc:    startService,
		startDetach: func() error { return startDetached(filepath.Join(paths.State(), "daemon.log"), nil) },
		wait: func() error {
			c, err := dialRetry(5 * time.Second)
			if err == nil {
				c.Close()
			}
			return err
		},
		login: func() (string, error) {
			c, err := dialRetry(2 * time.Second)
			if err != nil {
				return "", err
			}
			defer c.Close()
			var r daemon.UILoginReply
			if err := c.Call("A.UILogin", &daemon.Empty{}, &r); err != nil {
				return "", fmt.Errorf("%v (daemon started with --no-ui?)", err)
			}
			return r.URL, nil
		},
		browse: approval.OpenURL,
	})
	if err != nil {
		// No terminal behind an app icon: tell the user on the desktop too.
		approval.Notify(approval.Notice{Title: "Ostiary", Body: "Không mở được Ostiary: " + err.Error()})
		return errf(1, "%v", err)
	}
	return 0
}

func cmdStop(args []string) int {
	if !daemon.Running() {
		fmt.Println("daemon is not running")
		return 0
	}
	c, code := dial()
	if c == nil {
		return code
	}
	defer c.Close()
	if err := c.Call("A.Shutdown", &daemon.Empty{}, &daemon.Empty{}); err != nil {
		return callErr(err)
	}
	for i := 0; i < 50 && daemon.Running(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("daemon stopped")
	return 0
}
```

Notes:
- `startDetached` prints a line to stdout. In the GUI build stdout is discarded, which is harmless.
- `startDetached` on Windows already uses `CREATE_NO_WINDOW`. Because it re-executes `os.Executable()`, a daemon started from `ostiary-app.exe` is itself the GUI build and shows no console.

In `cli.go`:
- register `"open": cmdOpen` and `"stop": cmdStop`;
- add usage lines: `open` opens the Ostiary app (starting the daemon if needed); `stop` stops the daemon;
- at the top of `Main`, if `len(args) == 0` and `appDefault(os.Executable())` is true, run `cmdOpen(nil)`.

`startService()`:
- Linux: `systemctl --user start ostiary.service`.
- macOS: `launchctl kickstart gui/<uid>/dev.ostiary`. If that fails (plist written but not loaded), run `launchctl load -w <plist>`. Get the uid from `os.Getuid()`.
- Windows: `schtasks /Run /TN ostiary`.

`Shutdown` RPC:
- Store the listener passed to `Serve`/`ServeListener` on the `Daemon`, under the mutex.
- `Shutdown` writes an audit entry `{Kind:"admin", Cmd:"stop", Decision:"allow"}` and then closes the listener in a goroutine after replying, so the RPC returns before the socket goes away.
- Make sure `Serve`'s return on a closed listener counts as clean shutdown, so `cmdDaemon` returns 0 rather than logging an error. Check how `Serve` handles `net.ErrClosed`.

Add a daemon test: `Shutdown` makes `ServeListener` return nil within 2s and `Running()` false.

`hookCommand` must use `cliExe()`. A hook must run the console build so agents get its stdout. Implement `cliExe()`: on Windows, if `appDefault(exe)` is true, return the sibling `ostiary.exe` (error if it is missing); otherwise return `exe`.

`hook.go`: add `open` and `stop` to the human-only set, with test rows.

- [ ] **Step 3: Run tests, verify, commit**

Run `go test ./internal/cli/ ./internal/daemon/ ./internal/hook/`, which should pass. Then run the full local check list. Then:

```bash
git add -A
git commit -m "feat: ostiary open/stop, Shutdown RPC, Windows GUI build runs open by default

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Linux menu entry from `install-service`

**Files:**
- Create: `internal/cli/desktop_linux.go`, `internal/cli/desktop_linux_test.go`
- Modify: `internal/cli/os_unix.go` (`installService` calls `installDesktop()` on Linux)

**Interfaces:**
- Produces:
  - `func desktopEntry(exe string) string`;
  - `func installDesktop(home, exe string) error`, which writes `~/.local/share/applications/ostiary.desktop` and `~/.local/share/icons/hicolor/<n>x<n>/apps/ostiary.png` for n in 16, 32, 48, 64, 128, 256, 512.
- Consumes: `brand.PNG(int)`.

- [ ] **Step 1: Failing test**

```go
//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ASromancer/ostiary/internal/brand"
)

func TestInstallDesktop(t *testing.T) {
	home := t.TempDir()
	if err := installDesktop(home, "/opt/o s/ostiary"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(home, ".local/share/applications/ostiary.desktop"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Desktop Entry]", "Name=Ostiary", `Exec="/opt/o s/ostiary" open`, "Icon=ostiary", "Terminal=false", "Type=Application"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q in\n%s", want, b)
		}
	}
	p, _ := os.ReadFile(filepath.Join(home, ".local/share/icons/hicolor/256x256/apps/ostiary.png"))
	if string(p) != string(brand.PNG(256)) {
		t.Fatal("icon not written")
	}
}
```

Run it and check that it fails.

- [ ] **Step 2: Implement**

```go
//go:build linux

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ASromancer/ostiary/internal/brand"
)

func desktopEntry(exe string) string {
	return fmt.Sprintf("[Desktop Entry]\nType=Application\nName=Ostiary\n"+
		"Comment=Người gác cửa giữa AI agent và máy chủ của bạn\n"+
		"Exec=%q open\nIcon=ostiary\nTerminal=false\nCategories=Utility;Security;\nStartupNotify=false\n", exe)
}

// installDesktop adds Ostiary to the desktop's application menu.
func installDesktop(home, exe string) error {
	for _, n := range []int{16, 32, 48, 64, 128, 256, 512} {
		p := filepath.Join(home, ".local/share/icons/hicolor", fmt.Sprintf("%dx%d", n, n), "apps", "ostiary.png")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, brand.PNG(n), 0o644); err != nil {
			return err
		}
	}
	p := filepath.Join(home, ".local/share/applications", "ostiary.desktop")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(desktopEntry(exe)), 0o644); err != nil {
		return err
	}
	_ = exec.Command("update-desktop-database", filepath.Dir(p)).Run() // optional; menus also rescan
	return nil
}
```

`%q` quoting matches the Desktop Entry spec's double-quoted Exec arguments for ordinary paths. In `installService` (Linux branch, both `startNow` values), call `installDesktop(home, exe)` after writing the unit, unless `exe` is under `/usr/` (the `.deb` already ships the system entry). On failure, print a warning; it is not fatal. `removeService` leaves the menu entry, because turning autostart off is not uninstalling.

- [ ] **Step 3: Verify and commit**

Run the tests, then the full local check list.

```bash
git add internal/cli
git commit -m "feat(linux): install-service adds Ostiary to the application menu

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Packaging sources

**Files:**
- Create: `packaging/linux/nfpm.yaml`, `packaging/linux/ostiary.desktop`, `packaging/linux/ostiary.service`
- Create: `packaging/macos/Info.plist.in`, `packaging/macos/Ostiary` (launcher, mode 755), `packaging/macos/build-app.sh`
- Create: `packaging/windows/ostiary.iss`
- Create: `packaging/README.md` (how each artefact is built, run locally where possible)
- Modify: `internal/cli/human.go` (`install-service --yes` skips the TTY requirement, like `uninstall-service --yes`)

**Interfaces:**
- The CI (Task 4) calls:
  - `nfpm package -f packaging/linux/nfpm.yaml -p deb -t dist/`, with env `VERSION` and `ARCH` (`amd64`/`arm64`) and the binary at `build/linux-$ARCH/ostiary`;
  - `packaging/macos/build-app.sh VERSION UNIVERSAL_BIN ICNS OUTDIR`, which writes `OUTDIR/Ostiary.app` and `OUTDIR/Ostiary-VERSION.dmg`;
  - `iscc /DVersion=VERSION /DSrcDir=DIR /DOutDir=DIR packaging\windows\ostiary.iss`, with `DIR` holding `ostiary.exe`, `ostiary-app.exe` and `ostiary.ico`.

- [ ] **Step 1: Linux files**

`packaging/linux/ostiary.desktop`:

```ini
[Desktop Entry]
Type=Application
Name=Ostiary
Comment=Người gác cửa giữa AI agent và máy chủ của bạn
Exec=ostiary open
Icon=ostiary
Terminal=false
Categories=Utility;Security;
StartupNotify=false
```

`packaging/linux/ostiary.service` must be byte-identical in meaning to `systemdUnit("/usr/bin/ostiary")` in `os_unix.go`. Add a Linux test that reads this file and compares it with `systemdUnit("/usr/bin/ostiary")`, so the two cannot drift:

```ini
[Unit]
Description=Ostiary daemon
After=graphical-session.target
PartOf=graphical-session.target

[Service]
ExecStart=/usr/bin/ostiary daemon
Restart=on-failure

[Install]
WantedBy=graphical-session.target
```

Adjust it to whatever `systemdUnit` actually produces after the rename (for example the `Description` capitalisation), then make both match exactly.

`packaging/linux/nfpm.yaml`:

```yaml
name: ostiary
arch: ${ARCH}
platform: linux
version: ${VERSION}
section: utils
priority: optional
maintainer: ASromancer <65549952+ASromancer@users.noreply.github.com>
description: |
  The doorkeeper between AI agents and your servers: AI coding agents run
  SSH commands through Ostiary without ever seeing private keys.
homepage: https://github.com/ASromancer/ostiary
license: MIT
contents:
  - src: build/linux-${ARCH}/ostiary
    dst: /usr/bin/ostiary
    file_info: { mode: 0755 }
  - src: packaging/linux/ostiary.desktop
    dst: /usr/share/applications/ostiary.desktop
  - src: packaging/linux/ostiary.service
    dst: /usr/lib/systemd/user/ostiary.service
  - src: build/icons/16.png
    dst: /usr/share/icons/hicolor/16x16/apps/ostiary.png
  - src: build/icons/32.png
    dst: /usr/share/icons/hicolor/32x32/apps/ostiary.png
  - src: build/icons/48.png
    dst: /usr/share/icons/hicolor/48x48/apps/ostiary.png
  - src: build/icons/64.png
    dst: /usr/share/icons/hicolor/64x64/apps/ostiary.png
  - src: build/icons/128.png
    dst: /usr/share/icons/hicolor/128x128/apps/ostiary.png
  - src: build/icons/256.png
    dst: /usr/share/icons/hicolor/256x256/apps/ostiary.png
  - src: build/icons/512.png
    dst: /usr/share/icons/hicolor/512x512/apps/ostiary.png
```

Check the repo's LICENSE and use its actual licence id. The CI copies `internal/brand/png/ostiary-<n>.png` to `build/icons/<n>.png`.

- [ ] **Step 2: macOS files**

`packaging/macos/Ostiary` (launcher, `chmod 755`):

```sh
#!/bin/sh
exec "$(dirname "$0")/ostiary" open
```

`packaging/macos/Info.plist.in` (`@VERSION@` is substituted):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Ostiary</string>
  <key>CFBundleDisplayName</key><string>Ostiary</string>
  <key>CFBundleIdentifier</key><string>dev.ostiary.app</string>
  <key>CFBundleExecutable</key><string>Ostiary</string>
  <key>CFBundleIconFile</key><string>ostiary</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>@VERSION@</string>
  <key>CFBundleVersion</key><string>@VERSION@</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSUIElement</key><true/>
</dict></plist>
```

`packaging/macos/build-app.sh`:

```sh
#!/bin/sh
# Usage: build-app.sh VERSION UNIVERSAL_BIN ICNS OUTDIR
set -eu
ver=$1 bin=$2 icns=$3 out=$4
here=$(cd "$(dirname "$0")" && pwd)
app="$out/Ostiary.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
sed "s/@VERSION@/$ver/g" "$here/Info.plist.in" > "$app/Contents/Info.plist"
cp "$here/Ostiary" "$app/Contents/MacOS/Ostiary"
cp "$bin" "$app/Contents/MacOS/ostiary"
chmod 755 "$app/Contents/MacOS/Ostiary" "$app/Contents/MacOS/ostiary"
cp "$icns" "$app/Contents/Resources/ostiary.icns"
plutil -lint "$app/Contents/Info.plist"
stage=$(mktemp -d)
cp -R "$app" "$stage/"
ln -s /Applications "$stage/Applications"
hdiutil create -volname Ostiary -srcfolder "$stage" -ov -format UDZO "$out/Ostiary-$ver.dmg"
rm -rf "$stage"
```

- [ ] **Step 3: Windows installer script**

`packaging/windows/ostiary.iss`:

```ini
#ifndef Version
  #define Version "0.0.0"
#endif
#ifndef SrcDir
  #define SrcDir "."
#endif
#ifndef OutDir
  #define OutDir "."
#endif

[Setup]
AppId={{6C0B7E1A-3F2D-4E7B-9A51-0D2F7C9E4B10}
AppName=Ostiary
AppVersion={#Version}
AppPublisher=ASromancer
AppPublisherURL=https://github.com/ASromancer/ostiary
DefaultDirName={userpf}\Ostiary
DefaultGroupName=Ostiary
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutDir}
OutputBaseFilename=Ostiary-Setup-{#Version}-x64
SetupIconFile={#SrcDir}\ostiary.ico
UninstallDisplayIcon={app}\ostiary.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
CloseApplications=no

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "autostart"; Description: "Start Ostiary when I sign in"

[Files]
Source: "{#SrcDir}\ostiary.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\ostiary-app.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\ostiary.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\Ostiary"; Filename: "{app}\ostiary-app.exe"; IconFilename: "{app}\ostiary.ico"
Name: "{userdesktop}\Ostiary"; Filename: "{app}\ostiary-app.exe"; IconFilename: "{app}\ostiary.ico"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\ostiary.exe"; Parameters: "install-service --yes"; Flags: runhidden; Tasks: autostart
Filename: "{app}\ostiary-app.exe"; Description: "Open Ostiary"; Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "{app}\ostiary.exe"; Parameters: "stop"; Flags: runhidden; RunOnceId: "stop"
Filename: "{app}\ostiary.exe"; Parameters: "uninstall-service --yes"; Flags: runhidden; RunOnceId: "unsvc"

[Code]
function NeedsAddPath(Dir: string): Boolean;
var
  Paths: string;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', Paths) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') = 0;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  { An upgrade over a running daemon: stop it so its files can be replaced. }
  if FileExists(ExpandConstant('{app}\ostiary.exe')) then
    Exec(ExpandConstant('{app}\ostiary.exe'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := '';
end;
```

Removing the PATH entry on uninstall is skipped. An extra PATH entry pointing at a deleted directory is harmless; README mentions it.

`install-service --yes`: in `cmdInstallService`, accept the flag `--yes` (parse it with `newFlags`). When it is set, skip `openTTY`. Agents still cannot run the command, because `install-service` is human-only in the hook.

- [ ] **Step 4: `packaging/README.md`**

Document, for each artefact:
- what builds it;
- the exact CI commands;
- how to build the `.deb` locally (`go install github.com/goreleaser/nfpm/v2/cmd/nfpm@<pinned>`, then the same command as in CI).

Build the `.deb` locally once and check it with `dpkg-deb -c` and `dpkg-deb -I`:
- `go run ./tools/brandgen`;
- copy the PNGs to `build/icons`;
- build `build/linux-amd64/ostiary`;
- run `VERSION=0.0.0-dev ARCH=amd64 nfpm package …`.

`build/` and `dist/` must be in `.gitignore`.

- [ ] **Step 5: Commit**

```bash
git add packaging internal/cli .gitignore
git commit -m "build: packaging sources for .deb, macOS .app/.dmg and Windows installer

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: CI builds, smoke-tests and attaches every artefact

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md` (an install section per OS)

**Interfaces:**
- Consumes: the commands from Task 3; `go run ./tools/brandgen -out DIR`.
- Produces release assets (names exact):
  - `ostiary-linux-amd64.tar.gz` and `ostiary-linux-arm64.tar.gz` (each with `ostiary`, `LICENSE`, `README.md`);
  - `ostiary_<ver>_amd64.deb` and `ostiary_<ver>_arm64.deb`;
  - `ostiary-windows-amd64.zip` and `ostiary-windows-arm64.zip` (each with `ostiary.exe`, `ostiary-app.exe`);
  - `Ostiary-Setup-<ver>-x64.exe`;
  - `Ostiary-<ver>.dmg`;
  - `ostiary-darwin-universal.tar.gz` (the `ostiary` binary);
  - `SHA256SUMS`.

- [ ] **Step 1: Version string**

Every build job computes the version once:

```bash
if [[ "$GITHUB_REF" == refs/tags/v* ]]; then VERSION=${GITHUB_REF_NAME#v}; else VERSION=0.0.0-dev.$(git rev-parse --short HEAD); fi
echo "VERSION=$VERSION" >> "$GITHUB_ENV"
```

All `-X …/internal/cli.Version=` flags use `$VERSION`.

- [ ] **Step 2: Jobs**

Keep `test` unchanged.

Replace `build-unix-windows` with `build-linux-windows` (ubuntu-latest):
- Linux amd64 and arm64: build `build/linux-$a/ostiary` and tar it.
- Windows amd64 and arm64: build `ostiary.exe` and `ostiary-app.exe` (`-ldflags "-s -w -H=windowsgui -X …"`), then zip both.
- `go run ./tools/brandgen -out build/brand`, then copy the PNGs to `build/icons`.
- `go install github.com/goreleaser/nfpm/v2/cmd/nfpm@<pinned>`, then build the `.deb` for both architectures.
- Smoke checks:
  - `dpkg-deb -c` lists `/usr/bin/ostiary`, the `.desktop` file and the user unit;
  - `dpkg-deb -I` shows the version;
  - installing the amd64 `.deb` into the runner (`sudo apt-get install -y ./dist/ostiary_*_amd64.deb`) makes `ostiary version` print `$VERSION`.
- Marker check on every binary.
- Upload `dist/` and also `build/windows-amd64/` (the exes plus `build/brand/ostiary.ico`) as artifact `win-installer-input`.

Change `build-macos` (macos-latest):
- build amd64 and arm64 with cgo as today;
- `lipo -create -output build/ostiary-universal …`;
- `lipo -info` must list both architectures;
- `go run ./tools/brandgen -out build/brand`;
- `sh packaging/macos/build-app.sh "$VERSION" build/ostiary-universal build/brand/ostiary.icns dist`;
- smoke check: `hdiutil attach -nobrowse -mountpoint /tmp/ost dist/Ostiary-*.dmg`, then check that `/tmp/ost/Ostiary.app/Contents/MacOS/ostiary version` prints `$VERSION` and that `Info.plist` lints, then `hdiutil detach /tmp/ost`;
- tar the universal binary;
- marker check;
- upload.

New job `build-windows-installer`, runs on windows-latest and needs `build-linux-windows`:
- download `win-installer-input`;
- locate `ISCC.exe` (`"${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"`); if it is missing, `choco install innosetup -y --no-progress`;
- run `ISCC.exe /DVersion=$env:VERSION /DSrcDir=<input dir> /DOutDir=dist packaging\windows\ostiary.iss`;
- smoke check: `Start-Process dist\Ostiary-Setup-*.exe -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/TASKS=""','/DIR=C:\ost' -Wait`, then `C:\ost\ostiary.exe version` must print `$env:VERSION`;
- upload `dist/`.

The `/TASKS=""` value means no autostart on the runner. Check Inno's syntax for "no tasks"; it may be `/MERGETASKS="!autostart"`.

`release` needs all three build jobs. It merges the artifacts, writes `SHA256SUMS` over every file in `dist/`, and runs `gh release create` on tags as today.

- [ ] **Step 3: README install section**

Replace the install instructions with a section per OS:
- **Windows**: run `Ostiary-Setup-…-x64.exe`. SmartScreen: "More info → Run anyway". Start Menu → Ostiary.
- **macOS**: open the `.dmg` and drag the app to Applications. First launch: right-click → Open (unsigned). Optional CLI symlink command.
- **Debian/Ubuntu**: `sudo apt install ./ostiary_<ver>_amd64.deb`, then open "Ostiary" from the app menu. Optional `sudo "$(command -v ostiary)" install-polkit`.
- **Other Linux**: use the tarball, then run `ostiary install-service` (this adds the menu entry and autostart).

Keep the existing CLI and agent docs below.

- [ ] **Step 4: Push and verify CI (the controller does the push)**

Commit, then report. The controller pushes the branch and watches CI. If a packaging job fails, the controller sends back the failing log lines and you fix them in the same task.

```bash
git add .github/workflows/ci.yml README.md
git commit -m "ci: build and smoke-test .deb, .dmg, Windows installer and archives

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
