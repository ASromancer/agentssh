# agentssh OS Authentication Implementation Plan (GUI plan A of 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 4-character approval codes with operating-system authentication (polkit, Touch ID / macOS password, Windows password) that the daemon itself triggers, keeping codes as the fallback.

**Architecture:** A new `internal/humanok` package exposes `Confirmer{Available() error; Confirm(ctx, msg) error}` with one implementation per OS. The daemon calls it before approving a request or running an admin operation, so a caller of the daemon API (GUI, CLI, or an agent) cannot approve anything without the human passing the OS dialog. When `Available()` fails (no graphical session, polkit action not installed), every path falls back to the existing code flow unchanged.

**Tech Stack:** Go 1.26, stdlib, `golang.org/x/sys` (already a dependency), cgo only on macOS (LocalAuthentication). No new modules.

**Spec:** `docs/superpowers/specs/2026-11-11-agentssh-gui-design.md` (sections 4 and 8). Plan B (web UI, tray, notifications: spec sections 5–7) is written after this plan lands, using the spike results from Task 1.

## Global Constraints

- Platforms: Linux, macOS, Windows; amd64 and arm64 (spec §2.3).
- Single binary; no frontend build step (spec §2.4).
- No new Go modules in this plan. `fyne.io/systray` arrives in plan B.
- cgo only for macOS. Linux and Windows release builds stay `CGO_ENABLED=0`.
- The OS dialog text is built by the daemon from its own data (host, original command, level), never from agent text (spec §4.1).
- One authentication per action; the only standing grant remains `s` (same command, same host, 30 min) (spec §4.1).
- Denials (`n`, `m`) need no authentication (spec §4.2).
- Fallback is the existing code flow, byte-for-byte compatible (spec §4.4).
- The fake confirmer exists only under the build tag `e2efake`; release builds never contain it (spec §9).
- Git: commit as `ASromancer <65549952+ASromancer@users.noreply.github.com>` (repo-local config is already set). End every commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Go toolchain: `export PATH=$HOME/.local/sdk/go/bin:$PATH` before any `go` command.

## File Structure

| File | Responsibility |
|---|---|
| `internal/humanok/humanok.go` (create) | `Confirmer` interface, errors, `Default`, `Fake`, polkit constants and `PolicyXML`, `InstallPolicy()` |
| `internal/humanok/linux.go` (create) | polkit implementation via `pkcheck` |
| `internal/humanok/darwin_cgo.go` (create) | LocalAuthentication implementation (cgo) |
| `internal/humanok/darwin_nocgo.go` (create) | "unavailable" stub for `CGO_ENABLED=0` macOS builds |
| `internal/humanok/windows.go` (create) | CredUI prompt + `LogonUserW` check |
| `internal/humanok/e2efake.go` (create) | file-driven confirmer, build tag `e2efake` only |
| `internal/humanok/linux_test.go`, `humanok_test.go` (create) | unit tests |
| `internal/approval/approval.go` (modify) | `UseCodes`, `Decision.Auth`, `Resolve`, `Get`, `Take` |
| `internal/audit/audit.go` (modify) | `Entry.Auth` |
| `internal/daemon/{daemon,service,admin,rpc}.go` (modify) | wire the confirmer into Decide/Begin/Admin/Unlock/Status/Exec |
| `internal/cli/{cli,human}.go` (modify) | approve/admin flows without codes, `install-polkit`, doctor |
| `scripts/e2e.py` (modify) | OS-auth scenario using the `e2efake` binary |
| `.github/workflows/ci.yml` (modify) | macOS release built natively with cgo; e2efake e2e step |
| `README.md`, spec §4.5 (modify) | docs and spike results |

---

### Task 1: Spike — polkit from the daemon's context (manual, needs the user)

**Files:**
- Modify: `docs/superpowers/specs/2026-11-11-agentssh-gui-design.md` (§4.5: record results)

This task answers spec §4.5 risks 1 and 2 on the Linux machine at hand. It needs the user at the desktop: polkit dialogs appear on their screen, and the policy install needs `sudo`. The agent prepares commands; the user runs the `sudo` step and clicks the dialogs.

- [ ] **Step 1: Write the test policy to a temp file (agent)**

```bash
cat > /tmp/dev.agentssh.policy <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>agentssh</vendor>
  <vendor_url>https://github.com/ASromancer/agentssh</vendor_url>
  <action id="dev.agentssh.confirm">
    <description>Confirm an agentssh action</description>
    <message>agentssh: $(message)</message>
    <defaults>
      <allow_any>auth_self</allow_any>
      <allow_inactive>auth_self</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
  </action>
</policyconfig>
EOF
```

- [ ] **Step 2: User installs it**

Ask the user to run in their own terminal:

```bash
sudo install -m 0644 /tmp/dev.agentssh.policy /usr/share/polkit-1/actions/dev.agentssh.policy
```

- [ ] **Step 3: Variant A, from a desktop terminal (user)**

```bash
pkcheck --action-id dev.agentssh.confirm --process $$ --allow-user-interaction --detail message "approve on VMT_DWH: rm -rf /tmp/x [destructive]"; echo "exit=$?"
```

Record:
- Does a dialog appear?
- Does it show the command text, i.e. does `$(message)` expand?
- The exit code for: correct password, Cancel, and a wrong password 3 times.

- [ ] **Step 4: Variant B, from a systemd user service, like the daemon (user)**

```bash
systemd-run --user --wait --pipe --quiet sh -c 'pkcheck --action-id dev.agentssh.confirm --process $$ --allow-user-interaction --detail message "from systemd --user"; echo "exit=$?"'
```

Record whether a dialog appears and the exit code.

- [ ] **Step 5: Variant C, B with the graphical environment imported (user)**

```bash
systemctl --user import-environment DISPLAY WAYLAND_DISPLAY XAUTHORITY
systemd-run --user --wait --pipe --quiet sh -c 'echo DISPLAY=$DISPLAY; pkcheck --action-id dev.agentssh.confirm --process $$ --allow-user-interaction --detail message "from systemd --user + env"; echo "exit=$?"'
```

- [ ] **Step 6: Record results in spec §4.5 and pick the Linux service mode**

Rules:
- If B or C shows a dialog, keep the systemd user service. If only C works, Task 6 Step 6 adds `import-environment` to `install-hooks`.
- If only A works, Task 7 Step 6 switches the Linux service to XDG autostart, which runs inside the graphical session.
- If `$(message)` does not expand, the policy `<message>` becomes `agentssh needs your confirmation (details in the agentssh window or terminal)`, and the CLI and GUI print the command next to the prompt (Task 7 already prints it).

Append under §4.5 a "Spike results (Linux, <date>)" list with the observed facts.

- [ ] **Step 7: Commit**

```bash
git add docs/superpowers/specs/2026-11-11-agentssh-gui-design.md
git commit -m "docs: record polkit spike results

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `humanok` core and Linux polkit implementation

**Files:**
- Create: `internal/humanok/humanok.go`, `internal/humanok/linux.go`, `internal/humanok/humanok_test.go`, `internal/humanok/linux_test.go`

**Interfaces:**
- Produces:
  - `humanok.Confirmer` interface with `Available() error` and `Confirm(ctx context.Context, msg string) error`
  - `humanok.Default Confirmer`
  - `humanok.ErrDenied`, `humanok.ErrUnavailable`
  - `type Fake struct{ Err error; Allow bool }` with `func (f *Fake) Msgs() []string`
  - `humanok.ActionID`, `humanok.PolicyPath`, `func PolicyXML(owner string) string`, `func InstallPolicy() error`

- [ ] **Step 1: Write failing tests**

`internal/humanok/humanok_test.go`:

```go
package humanok

import (
	"context"
	"encoding/xml"
	"errors"
	"strings"
	"testing"
)

func TestFake(t *testing.T) {
	f := &Fake{Allow: true}
	if err := f.Confirm(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	f.Allow = false
	if err := f.Confirm(context.Background(), "b"); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v", err)
	}
	if got := strings.Join(f.Msgs(), ","); got != "a,b" {
		t.Fatalf("msgs %q", got)
	}
}

func TestPolicyXML(t *testing.T) {
	var p struct {
		Action struct {
			ID       string `xml:"id,attr"`
			Message  string `xml:"message"`
			Defaults struct {
				Active string `xml:"allow_active"`
			} `xml:"defaults"`
			Owner struct {
				Key   string `xml:"key,attr"`
				Value string `xml:",chardata"`
			} `xml:"annotate"`
		} `xml:"action"`
	}
	if err := xml.Unmarshal([]byte(PolicyXML("alice")), &p); err != nil {
		t.Fatal(err)
	}
	if p.Action.ID != ActionID || p.Action.Defaults.Active != "auth_self" || !strings.Contains(p.Action.Message, "$(message)") ||
		p.Action.Owner.Key != "org.freedesktop.policykit.owner" || p.Action.Owner.Value != "unix-user:alice" {
		t.Fatalf("%+v", p.Action)
	}
}
```

`internal/humanok/linux_test.go`:

```go
//go:build linux && !e2efake

package humanok

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestPkResult(t *testing.T) {
	for _, tc := range []struct {
		code int
		err  error
		want error
	}{
		{0, nil, nil},
		{1, nil, ErrDenied},
		{3, nil, ErrDenied},
		{2, nil, ErrUnavailable},
		{4, nil, ErrUnavailable},
		{-1, errors.New("exec: not found"), ErrUnavailable},
	} {
		if got := pkResult(tc.code, "", tc.err); !errors.Is(got, tc.want) && !(tc.want == nil && got == nil) {
			t.Errorf("code %d: got %v want %v", tc.code, got, tc.want)
		}
	}
}

func TestConfirmArgs(t *testing.T) {
	var args []string
	old := runPkcheck
	runPkcheck = func(_ context.Context, a ...string) (int, string, error) { args = a; return 0, "", nil }
	defer func() { runPkcheck = old }()
	if err := (platform{}).Confirm(context.Background(), "approve on web1: rm x [destructive]"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--action-id", ActionID, "--allow-user-interaction", "--detail", "message", "approve on web1: rm x [destructive]"} {
		if !slices.Contains(args, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/humanok/`
Expected: FAIL to build (`undefined: Fake`, `undefined: PolicyXML`, `undefined: pkResult`, …).

- [ ] **Step 3: Implement `humanok.go`**

```go
// Package humanok asks the operating system to confirm that the person at
// the machine approves an action: polkit on Linux, LocalAuthentication on
// macOS, the Windows credential prompt on Windows. The daemon calls it, so
// a caller of the daemon's API (GUI, CLI or an agent) still cannot approve
// anything without the human passing the OS dialog.
package humanok

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
)

var (
	ErrDenied      = errors.New("not confirmed by the user")
	ErrUnavailable = errors.New("OS authentication unavailable")
)

// Confirmer shows an OS authentication dialog.
type Confirmer interface {
	// Available returns nil when Confirm can show a dialog right now.
	Available() error
	// Confirm returns nil only if the user authenticated for msg.
	Confirm(ctx context.Context, msg string) error
}

// Default is the platform implementation.
var Default Confirmer = platform{}

// Fake is a Confirmer for tests.
type Fake struct {
	Err   error // returned by Available
	Allow bool

	mu   sync.Mutex
	msgs []string
}

func (f *Fake) Available() error { return f.Err }

func (f *Fake) Confirm(_ context.Context, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, msg)
	if f.Allow {
		return nil
	}
	return ErrDenied
}

func (f *Fake) Msgs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.msgs...)
}

// polkit action used on Linux.
const (
	ActionID   = "dev.agentssh.confirm"
	PolicyPath = "/usr/share/polkit-1/actions/dev.agentssh.policy"
)

// PolicyXML is the polkit action installed by 'sudo agentssh install-polkit'.
// auth_self (not auth_self_keep): every action needs its own
// authentication. polkit only lets uid 0 or an action owner pass details
// (the $(message) text), so the installing user is the owner.
func PolicyXML(owner string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>agentssh</vendor>
  <vendor_url>https://github.com/ASromancer/agentssh</vendor_url>
  <action id="dev.agentssh.confirm">
    <description>Confirm an agentssh action</description>
    <message>agentssh: $(message)</message>
    <defaults>
      <allow_any>auth_self</allow_any>
      <allow_inactive>auth_self</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.owner">unix-user:` + owner + `</annotate>
  </action>
</policyconfig>
`
}

// InstallPolicy writes the polkit action owned by the user who ran sudo.
// Linux only; needs root.
func InstallPolicy() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("polkit is only used on Linux; nothing to install on %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("run it with sudo: sudo agentssh install-polkit")
	}
	owner := os.Getenv("SUDO_USER")
	if owner == "" || owner == "root" || strings.ContainsAny(owner, "<>&\"'") {
		return errors.New("run it with sudo from your own account (SUDO_USER must name you)")
	}
	return os.WriteFile(PolicyPath, []byte(PolicyXML(owner)), 0o644)
}
```

(Spike result, spec §4.6: `$(message)` expands only with the owner annotation; the code above includes it.)

- [ ] **Step 4: Implement `linux.go`**

```go
//go:build linux && !e2efake

package humanok

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type platform struct{}

// pkcheck(1) exit codes.
const (
	pkAuthorized    = 0
	pkNotAuthorized = 1
	pkChallenge     = 2 // authorization needs interaction that could not happen
	pkDismissed     = 3
)

var runPkcheck = func(ctx context.Context, args ...string) (int, string, error) {
	out, err := exec.CommandContext(ctx, "pkcheck", args...).CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out), nil
	}
	if err != nil {
		return -1, string(out), err
	}
	return 0, string(out), nil
}

func (platform) Available() error {
	if _, err := os.Stat(PolicyPath); err != nil {
		return fmt.Errorf("%w: polkit action not installed (run: sudo agentssh install-polkit)", ErrUnavailable)
	}
	if _, err := exec.LookPath("pkcheck"); err != nil {
		return fmt.Errorf("%w: pkcheck not found (install polkit)", ErrUnavailable)
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return fmt.Errorf("%w: no graphical session", ErrUnavailable)
	}
	return nil
}

func (platform) Confirm(ctx context.Context, msg string) error {
	code, out, err := runPkcheck(ctx, "--action-id", ActionID, "--process", strconv.Itoa(os.Getpid()),
		"--allow-user-interaction", "--detail", "message", msg)
	return pkResult(code, out, err)
}

func pkResult(code int, out string, err error) error {
	switch {
	case err != nil:
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	case code == pkAuthorized:
		return nil
	case code == pkNotAuthorized || code == pkDismissed:
		return ErrDenied
	case code == pkChallenge:
		return fmt.Errorf("%w: no polkit authentication agent for this session", ErrUnavailable)
	}
	return fmt.Errorf("%w: pkcheck exit %d: %s", ErrUnavailable, code, strings.TrimSpace(out))
}
```

Spike result (spec §4.6): 0 = authenticated, 3 = Cancel, 2 = non-interactive; the mapping above matches.

- [ ] **Step 5: Add temporary stubs so other OSes still compile**

Tasks 3 and 4 replace these.

`internal/humanok/stub_other.go`:

```go
//go:build !linux && !e2efake

package humanok

import (
	"context"
	"fmt"
	"runtime"
)

type platform struct{}

func (platform) Available() error {
	return fmt.Errorf("%w: not implemented on %s yet", ErrUnavailable, runtime.GOOS)
}
func (platform) Confirm(context.Context, string) error { return ErrUnavailable }
```

- [ ] **Step 6: Run tests**

Run: `go test ./internal/humanok/ && GOOS=darwin go vet ./internal/humanok/ && GOOS=windows go vet ./internal/humanok/`
Expected: PASS, and vet clean on both other OSes.

- [ ] **Step 7: Commit**

```bash
git add internal/humanok
git commit -m "feat(humanok): OS confirmation interface and Linux polkit backend

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: macOS LocalAuthentication backend and native macOS release build

**Files:**
- Create: `internal/humanok/darwin_cgo.go`, `internal/humanok/darwin_nocgo.go`
- Modify: `internal/humanok/stub_other.go` (build tag becomes `!linux && !darwin && !e2efake`)
- Modify: `.github/workflows/ci.yml` (release job)

**Interfaces:**
- Consumes: `ErrDenied`, `ErrUnavailable`, and the `platform` type name from Task 2.

- [ ] **Step 1: Narrow the stub's build tag**

In `internal/humanok/stub_other.go`, replace the first line with:

```go
//go:build !linux && !darwin && !e2efake
```

(Windows keeps using the stub until Task 4.)

- [ ] **Step 2: `darwin_cgo.go`**

```go
//go:build darwin && cgo && !e2efake

package humanok

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>

static int la_available(void) {
	LAContext *c = [[LAContext alloc] init];
	return [c canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil] ? 1 : 0;
}

// 0 = authenticated, 1 = refused or cancelled, 2 = could not run.
static int la_confirm(const char *reason) {
	__block int result = 2;
	dispatch_semaphore_t sem = dispatch_semaphore_create(0);
	LAContext *c = [[LAContext alloc] init];
	[c evaluatePolicy:LAPolicyDeviceOwnerAuthentication
	  localizedReason:[NSString stringWithUTF8String:reason]
	            reply:^(BOOL ok, NSError *err) {
		if (ok) {
			result = 0;
		} else if (err.code == LAErrorUserCancel || err.code == LAErrorAuthenticationFailed ||
		           err.code == LAErrorAppCancel || err.code == LAErrorSystemCancel || err.code == LAErrorUserFallback) {
			result = 1;
		}
		dispatch_semaphore_signal(sem);
	}];
	dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
	return result;
}
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"
)

type platform struct{}

func (platform) Available() error {
	if C.la_available() == 0 {
		return fmt.Errorf("%w: LocalAuthentication cannot evaluate device-owner authentication", ErrUnavailable)
	}
	return nil
}

// ponytail: ctx is not honoured once the dialog is up (LAContext has no
// simple cancel from here); the dialog itself times out with the session.
func (platform) Confirm(_ context.Context, msg string) error {
	cs := C.CString(msg)
	defer C.free(unsafe.Pointer(cs))
	switch C.la_confirm(cs) {
	case 0:
		return nil
	case 1:
		return ErrDenied
	}
	return fmt.Errorf("%w: LocalAuthentication failed", ErrUnavailable)
}
```

- [ ] **Step 3: `darwin_nocgo.go`**

```go
//go:build darwin && !cgo && !e2efake

package humanok

import (
	"context"
	"fmt"
)

type platform struct{}

func (platform) Available() error {
	return fmt.Errorf("%w: this build has no cgo; use the official macOS release", ErrUnavailable)
}
func (platform) Confirm(context.Context, string) error { return ErrUnavailable }
```

- [ ] **Step 4: Build macOS releases natively with cgo**

In `.github/workflows/ci.yml`, replace the whole `release:` job with these three jobs:

```yaml
  build-unix-windows:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - run: |
          for t in linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
            os=${t%/*}; arch=${t#*/}; ext=""; [ "$os" = windows ] && ext=.exe
            GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath \
              -ldflags "-s -w -X github.com/ASromancer/agentssh/internal/cli.Version=${GITHUB_REF_NAME#v}" \
              -o dist/agentssh-$os-$arch$ext .
          done
      - uses: actions/upload-artifact@v4
        with: { name: dist-other, path: dist/ }
  build-macos:
    needs: test
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - run: |
          for arch in amd64 arm64; do
            cc_arch=$([ $arch = amd64 ] && echo x86_64 || echo arm64)
            CGO_ENABLED=1 GOOS=darwin GOARCH=$arch CC="clang -arch $cc_arch" go build -trimpath \
              -ldflags "-s -w -X github.com/ASromancer/agentssh/internal/cli.Version=${GITHUB_REF_NAME#v}" \
              -o dist/agentssh-darwin-$arch .
          done
      - uses: actions/upload-artifact@v4
        with: { name: dist-macos, path: dist/ }
  release:
    needs: [build-unix-windows, build-macos]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with: { path: dist, merge-multiple: true }
      - run: cd dist && sha256sum * > SHA256SUMS && ls -l
      - uses: actions/upload-artifact@v4
        with: { name: agentssh, path: dist/ }
      - if: startsWith(github.ref, 'refs/tags/v')
        env:
          GH_TOKEN: ${{ github.token }}
          GH_REPO: ${{ github.repository }}
        run: gh release create "$GITHUB_REF_NAME" dist/* --generate-notes
```

- [ ] **Step 5: Verify locally what can be verified**

Run: `GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go vet ./internal/humanok/ && go test ./internal/humanok/`
Expected: PASS. The cgo file is compiled only on the macOS runner.

- [ ] **Step 6: Commit and push, then check CI**

```bash
git add internal/humanok .github/workflows/ci.yml
git commit -m "feat(humanok): macOS LocalAuthentication backend; native cgo macOS builds

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin main
```

Expected: the `build-macos` job compiles `darwin_cgo.go` for both arches. If it fails, fix and push again before moving on.

---

### Task 4: Windows credential-prompt backend

**Files:**
- Create: `internal/humanok/windows.go`
- Modify: `internal/humanok/stub_other.go` (build tag becomes `!linux && !darwin && !windows && !e2efake`; after this it covers no supported OS and only keeps other GOOS values compiling)

**Interfaces:**
- Consumes: `ErrDenied`, `ErrUnavailable`, and the `platform` type name from Task 2.

- [ ] **Step 0: Narrow the stub**

Replace the first line of `internal/humanok/stub_other.go` with `//go:build !linux && !darwin && !windows && !e2efake`.

- [ ] **Step 1: Implement**

```go
//go:build windows && !e2efake

package humanok

import (
	"context"
	"fmt"
	"os/user"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	credui     = windows.NewLazySystemDLL("credui.dll")
	advapi     = windows.NewLazySystemDLL("advapi32.dll")
	ole32      = windows.NewLazySystemDLL("ole32.dll")
	procPrompt = credui.NewProc("CredUIPromptForWindowsCredentialsW")
	procPack   = credui.NewProc("CredPackAuthenticationBufferW")
	procUnpack = credui.NewProc("CredUnPackAuthenticationBufferW")
	procLogon  = advapi.NewProc("LogonUserW")
	procFree   = ole32.NewProc("CoTaskMemFree")
)

type creduiInfo struct {
	cbSize         uint32
	hwndParent     uintptr
	pszMessageText *uint16
	pszCaptionText *uint16
	hbmBanner      uintptr
}

const (
	creduiwinGeneric     = 0x1
	creduiwinInCredOnly  = 0x20
	errorCancelled       = 1223
	logonInteractive     = 2
	logonProviderDefault = 0
)

type platform struct{}

func (platform) Available() error {
	for _, p := range []*windows.LazyProc{procPrompt, procPack, procUnpack, procLogon, procFree} {
		if err := p.Find(); err != nil {
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	return nil
}

func ptr[T any](p *T) uintptr { return uintptr(unsafe.Pointer(p)) }

// Confirm asks for the current user's Windows password and checks it with
// LogonUserW; the resulting token must belong to the user running agentssh.
// ponytail: ctx is not honoured while the modal prompt is open.
func (platform) Confirm(_ context.Context, msg string) error {
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	caption, _ := windows.UTF16PtrFromString("agentssh")
	text, _ := windows.UTF16PtrFromString(msg)
	info := creduiInfo{cbSize: uint32(unsafe.Sizeof(creduiInfo{})), pszMessageText: text, pszCaptionText: caption}

	// Pre-fill the current account so the prompt asks only for its password.
	name, _ := windows.UTF16PtrFromString(u.Username)
	empty, _ := windows.UTF16PtrFromString("")
	var inSize uint32
	procPack.Call(0, ptr(name), ptr(empty), 0, ptr(&inSize))
	in := make([]byte, inSize)
	if r, _, e := procPack.Call(0, ptr(name), ptr(empty), ptr(&in[0]), ptr(&inSize)); r == 0 {
		return fmt.Errorf("%w: pack: %v", ErrUnavailable, e)
	}

	var authPkg, outSize uint32
	var out uintptr
	var save int32
	r, _, _ := procPrompt.Call(ptr(&info), 0, ptr(&authPkg), ptr(&in[0]), uintptr(inSize),
		ptr(&out), ptr(&outSize), ptr(&save), creduiwinGeneric|creduiwinInCredOnly)
	if r == errorCancelled {
		return ErrDenied
	}
	if r != 0 {
		return fmt.Errorf("%w: credential prompt error %d", ErrUnavailable, r)
	}
	defer procFree.Call(out)

	var userBuf, domBuf, passBuf [512]uint16
	un, dn, pn := uint32(len(userBuf)), uint32(len(domBuf)), uint32(len(passBuf))
	defer clear(passBuf[:])
	if r, _, e := procUnpack.Call(0, out, uintptr(outSize), ptr(&userBuf[0]), ptr(&un),
		ptr(&domBuf[0]), ptr(&dn), ptr(&passBuf[0]), ptr(&pn)); r == 0 {
		return fmt.Errorf("%w: unpack: %v", ErrUnavailable, e)
	}
	account := windows.UTF16ToString(userBuf[:])
	domain := windows.UTF16ToString(domBuf[:])
	if d, n, ok := strings.Cut(account, `\`); ok && domain == "" {
		domain, account = d, n
	}
	acc16, _ := windows.UTF16PtrFromString(account)
	dom16, _ := windows.UTF16PtrFromString(domain)
	var tok windows.Token
	if r, _, _ := procLogon.Call(ptr(acc16), ptr(dom16), ptr(&passBuf[0]), logonInteractive, logonProviderDefault, ptr(&tok)); r == 0 {
		return ErrDenied
	}
	defer tok.Close()
	got, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !windows.EqualSid(got.User.Sid, me.User.Sid) {
		return fmt.Errorf("%w: credentials of another account", ErrDenied)
	}
	return nil
}
```

- [ ] **Step 2: Vet**

Run: `GOOS=windows GOARCH=amd64 go vet ./internal/humanok/ && GOOS=windows GOARCH=arm64 go vet ./internal/humanok/`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add internal/humanok/windows.go internal/humanok/stub_other.go
git commit -m "feat(humanok): Windows credential prompt backend

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

(Manual verification on a Windows desktop is part of Task 7's checklist. Windows Hello PIN-only accounts may be refused by `LogonUserW`; record what happens and keep code fallback documented.)

---

### Task 5: approval queue — auth-agnostic resolution

**Files:**
- Modify: `internal/approval/approval.go`
- Test: `internal/approval/approval_test.go`

**Interfaces:**
- Produces:
  - `Queue.UseCodes func() bool` field: nil means codes are used.
  - `Decision.Auth string`: `"code"`, `"os"` or `"none"`.
  - `func (q *Queue) Resolve(id int, choice, msg, auth string) (Decision, error)`
  - `func (q *Queue) Get(id int) (Request, bool)`
  - `func (q *Queue) Take(id int, op string) (any, error)`

- [ ] **Step 1: Write failing tests**

Append to `internal/approval/approval_test.go`:

```go
func TestResolveWithoutCode(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	q.UseCodes = func() bool { return false }
	q.Add(Request{ID: 11, Host: "web1", Cmd: "rm x", Level: "destructive"})
	if strings.Contains(s.last, "code:") {
		t.Fatalf("notification leaks a code in OS-auth mode: %q", s.last)
	}
	if r, ok := q.Get(11); !ok || r.Cmd != "rm x" || r.Code != "" {
		t.Fatalf("get: %+v %v", r, ok)
	}
	if _, err := q.Resolve(11, "s", "", "os"); err != nil {
		t.Fatal(err)
	}
	_, d, _ := q.Wait(11)
	if !d.OK || d.Auth != "os" || !d.CodeOK || !q.Sticky("web1", "rm x") {
		t.Fatalf("%+v", d)
	}
	if _, err := q.Resolve(11, "y", "", "os"); err == nil {
		t.Fatal("resolved twice")
	}
}

func TestCodeDecisionAuth(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	q.Add(Request{ID: 12})
	q.Decide(12, s.code(), "y", "")
	if _, d, _ := q.Wait(12); d.Auth != "code" {
		t.Fatalf("auth %q", d.Auth)
	}
}

func TestTakeTicket(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	q.UseCodes = func() bool { return false }
	s.last = ""
	id, code := q.Ticket("key-rm a", "", 7)
	if code != "" || s.last != "" {
		t.Fatalf("OS-auth tickets must not notify a code: %q %q", code, s.last)
	}
	if _, err := q.Take(id, "key-rm b"); err == nil {
		t.Fatal("ticket taken for another op")
	}
	id, _ = q.Ticket("key-rm a", "", 7)
	if v, err := q.Take(id, "key-rm a"); err != nil || v != 7 {
		t.Fatalf("%v %v", v, err)
	}
	if _, err := q.Take(id, "key-rm a"); err == nil {
		t.Fatal("ticket reused")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/approval/`
Expected: FAIL to build (`q.UseCodes undefined`, `q.Resolve undefined`, `d.Auth undefined`…).

- [ ] **Step 3: Implement**

In `internal/approval/approval.go`:

(a) Add `Auth` to `Decision`:

```go
type Decision struct {
	OK      bool
	Outcome string // approved|denied|timeout
	Message string // optional note from the human, passed back to the agent
	CodeOK  bool   // the human proved presence (code or OS authentication)
	Sticky  bool
	Auth    string // code|os|none
}
```

(b) Add the field to `Queue` (below `Timeout`):

```go
	// UseCodes reports whether approvals use out-of-band codes. When it
	// returns false, the daemon authenticates the human through the OS and
	// notifications carry no code. nil means true.
	UseCodes func() bool
```

and a helper:

```go
func (q *Queue) codes() bool { return q.UseCodes == nil || q.UseCodes() }
```

(c) In `Add`, replace the notify block with:

```go
	body := fmt.Sprintf("%s: %s [%s] code: %s", r.Host, r.Cmd, r.Level, e.code)
	if !q.codes() {
		body = fmt.Sprintf("%s: %s [%s] — open agentssh to approve", r.Host, r.Cmd, r.Level)
	}
	err := q.Notify("agentssh approval #"+fmt.Sprint(r.ID), body)
	if err != nil && q.codes() {
		e.req.Code = e.code
	}
```

(d) Replace the tail of `Decide` (everything from `q.mu.Unlock()` after the code check down to the end of the function) with a call to a shared resolver, and add `Resolve` and `Get`:

```go
	q.mu.Unlock()
	return q.Resolve(id, choice, msg, "code")
}

// Resolve applies a decision whose human proof was already checked by the
// caller (OS authentication), or that needs none (denials).
func (q *Queue) Resolve(id int, choice, msg, auth string) (Decision, error) {
	q.mu.Lock()
	e, ok := q.pending[id]
	decided := ok && e.decided
	q.mu.Unlock()
	if !ok || decided {
		return Decision{}, fmt.Errorf("no pending request #%d", id)
	}
	d := Decision{CodeOK: auth == "code" || auth == "os", Auth: auth}
	switch choice {
	case "y":
		d.OK, d.Outcome = true, "approved"
	case "s":
		d.OK, d.Outcome, d.Sticky = true, "approved", true
	case "n":
		d.Outcome = "denied"
	case "m":
		d.Outcome, d.Message = "denied", msg
	default:
		return Decision{}, fmt.Errorf("unknown choice %q", choice)
	}
	if d.OK && !d.CodeOK {
		return Decision{}, errors.New("approval needs a code or OS authentication")
	}
	q.finish(id, d)
	return d, nil
}

// Get returns a pending, undecided request.
func (q *Queue) Get(id int) (Request, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.pending[id]
	if !ok || e.decided {
		return Request{}, false
	}
	return e.req, true
}
```

(e) In `Ticket`, only notify in code mode:

```go
	if !q.codes() {
		return id, ""
	}
	if err := q.Notify("agentssh", body); err != nil {
		return id, t.code
	}
	return id, ""
```

(f) Add `Take`:

```go
// Take consumes a ticket without a code; the caller authenticates the
// human through the OS instead.
func (q *Queue) Take(id int, op string) (any, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	t, ok := q.tickets[id]
	delete(q.tickets, id)
	if !ok || t.op != op || time.Now().After(t.expires) {
		return nil, errors.New("approval ticket expired or invalid; start again")
	}
	return t.data, nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test -race ./internal/approval/ ./internal/daemon/`
Expected: PASS (daemon tests unchanged: code mode is still the default).

- [ ] **Step 5: Commit**

```bash
git add internal/approval
git commit -m "feat(approval): resolve decisions authenticated outside the queue

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Daemon — authenticate approvals and admin operations through the OS

**Files:**
- Modify: `internal/daemon/daemon.go` (field + New), `internal/daemon/service.go` (Decide, Status, Exec audit), `internal/daemon/admin.go` (Begin, Admin, Unlock), `internal/daemon/rpc.go` (StatusReply, BeginReply), `internal/audit/audit.go`
- Test: `internal/daemon/daemon_test.go`

**Interfaces:**
- Consumes: `humanok.Confirmer`, `humanok.Default`, `humanok.Fake`; `Queue.UseCodes`, `Resolve`, `Get`, `Take`, `Decision.Auth` (Task 5).
- Produces:
  - `StatusReply.Auth string` (`"os"` or `"code"`) and `StatusReply.AuthNote string`
  - `BeginReply.OSAuth bool`
  - `audit.Entry.Auth string` (json `auth`)
  - unexported `Daemon.human humanok.Confirmer` (tests set it)

- [ ] **Step 1: Write the failing test**

Append to `internal/daemon/daemon_test.go` (and add the import `"github.com/ASromancer/agentssh/internal/humanok"`):

```go
func TestOSAuth(t *testing.T) {
	h := setup(t)
	fake := &humanok.Fake{Allow: false}
	h.d.human = fake
	if err := h.call("Unlock", &UnlockArgs{Pass: "pw"}, &Empty{}); err != nil {
		t.Fatal(err)
	}
	var st StatusReply
	h.call("Status", &Empty{}, &st)
	if st.Auth != "os" {
		t.Fatalf("status auth %q", st.Auth)
	}

	victim := h.remote + "/osauth"
	os.WriteFile(victim, []byte("x"), 0o600)
	rm := ExecArgs{Cmd: "rm " + victim}
	r := h.exec(rm)
	if r.Pending == 0 {
		t.Fatalf("expected pending: %+v", r)
	}
	if strings.Contains(h.notes[len(h.notes)-1], "code:") {
		t.Fatal("notification carries a code in OS-auth mode")
	}
	// The OS dialog is refused: still pending, nothing ran.
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Choice: "y"}, &Empty{}); err == nil {
		t.Fatal("approved without OS authentication")
	}
	if msgs := fake.Msgs(); len(msgs) != 1 || !strings.Contains(msgs[0], "rm "+victim) || !strings.Contains(msgs[0], "destructive") {
		t.Fatalf("dialog text %q", msgs)
	}
	fake.Allow = true
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Choice: "y"}, &Empty{}); err != nil {
		t.Fatal(err)
	}
	rm.ApprovalID = r.Pending
	if r := h.exec(rm); r.Exit != 0 || r.Code != 0 {
		t.Fatalf("run after OS approval: %+v", r)
	}

	// Denial needs no authentication.
	before := len(fake.Msgs())
	r = h.exec(ExecArgs{Cmd: "rm -rf /tmp/never"})
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Choice: "n"}, &Empty{}); err != nil || len(fake.Msgs()) != before {
		t.Fatalf("deny: %v, dialogs %d", err, len(fake.Msgs())-before)
	}

	// Admin without a code.
	var br BeginReply
	h.call("Begin", &BeginArgs{Op: "key-gen", Name: "os1"}, &br)
	var ar AdminReply
	if !br.OSAuth {
		t.Fatal("Begin did not report OS auth")
	}
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Op: "key-gen", Name: "os1"}, &ar); err != nil || !strings.HasPrefix(ar.Out, "ssh-ed25519 ") {
		t.Fatalf("admin: %v %q", err, ar.Out)
	}
	if last := fake.Msgs()[len(fake.Msgs())-1]; !strings.Contains(last, "key-gen os1") {
		t.Fatalf("admin dialog %q", last)
	}

	b, _ := os.ReadFile(paths.Audit())
	if !bytes.Contains(b, []byte(`"auth":"os"`)) {
		t.Fatalf("audit lacks auth=os:\n%s", b)
	}
}
```

Note: `h.notes` is read without the harness lock here; guard it with `h.mu.Lock()/Unlock()` around the read if `-race` complains.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/daemon/ -run TestOSAuth`
Expected: FAIL to build (`h.d.human undefined`, `st.Auth undefined`, `br.OSAuth undefined`).

- [ ] **Step 3: RPC and audit fields**

`internal/daemon/rpc.go`:

```go
type StatusReply struct {
	Locked, UserOnly, Passphrase, VaultMissing bool
	Pending                                    int
	Auth                                       string // "os" or "code"
	AuthNote                                   string // why OS authentication is unavailable
}
```

```go
type BeginReply struct {
	Ticket int
	Info   string // e.g. host key fingerprint to compare
	Code   string // only when the desktop notification failed (code mode)
	OSAuth bool   // no code: Admin triggers an OS authentication dialog
}
```

`internal/audit/audit.go`, add to `Entry` after `CodeOK`:

```go
	Auth       string    `json:"auth,omitempty"` // code|os|passphrase|none
```

- [ ] **Step 4: Daemon field and queue mode**

`internal/daemon/daemon.go`: add the import `"github.com/ASromancer/agentssh/internal/humanok"`, add the field `human humanok.Confirmer` to `Daemon` (next to `q`), and in `New` after constructing `d`:

```go
	d.human = humanok.Default
	d.q.UseCodes = func() bool { return d.human.Available() != nil }
```

Add helpers to `daemon.go`:

```go
// osAuth reports whether the human is authenticated through the OS.
func (d *Daemon) osAuth() bool { return d.human.Available() == nil }

const confirmTimeout = 2 * time.Minute

func (d *Daemon) confirm(msg string) error {
	ctx, cancel := context.WithTimeout(context.Background(), confirmTimeout)
	defer cancel()
	return d.human.Confirm(ctx, msg)
}
```

(Add `"context"` to the imports.)

- [ ] **Step 5: Decide and Status**

`internal/daemon/service.go`, replace `Decide`:

```go
func (s *Service) Decide(a *DecideArgs, _ *Empty) error {
	d := s.d
	switch {
	case a.Choice == "n" || a.Choice == "m": // denying needs no proof
		_, err := d.q.Resolve(a.ID, a.Choice, a.Note, "none")
		return err
	case !d.osAuth():
		_, err := d.q.Decide(a.ID, a.Code, a.Choice, a.Note)
		return err
	}
	req, ok := d.q.Get(a.ID)
	if !ok {
		return fmt.Errorf("no pending request #%d", a.ID)
	}
	msg := fmt.Sprintf("approve on %s: %s [%s]", req.Host, req.Cmd, req.Level)
	if a.Choice == "s" {
		msg += " (and the same command for 30 minutes)"
	}
	if err := d.confirm(msg); err != nil {
		return err
	}
	_, err := d.q.Resolve(a.ID, a.Choice, a.Note, "os")
	return err
}
```

In `Status`, before `return nil`:

```go
	r.Auth = "code"
	if err := d.human.Available(); err == nil {
		r.Auth = "os"
	} else {
		r.AuthNote = err.Error()
	}
```

In `Exec`, in the `case a.ApprovalID != 0:` branch right after `e.ID, e.CodeOK = id, &dec.CodeOK`, add:

```go
			e.Auth = dec.Auth
```

- [ ] **Step 6: Begin, Admin, Unlock**

`internal/daemon/admin.go`:

In `Begin`, after `r.Ticket, r.Code = s.d.q.Ticket(...)`:

```go
	r.OSAuth = s.d.osAuth()
```

Replace the first lines of `Admin` (from `data, err := d.q.Check(...)` through `e.CodeOK = &ok`) with:

```go
	op := a.Op + " " + a.Name
	e := audit.Entry{Kind: "admin", Cmd: strings.TrimSpace(op), Auth: "code"}
	var data any
	var err error
	if d.osAuth() {
		e.Auth = "os"
		if data, err = d.q.Take(a.Ticket, op); err == nil {
			err = d.confirm(adminMessage(a, data))
		}
	} else {
		data, err = d.q.Check(a.Ticket, op, a.Code)
	}
	ok := err == nil
	e.CodeOK = &ok
```

and add:

```go
// adminMessage is the OS dialog text for an admin operation.
func adminMessage(a *AdminArgs, data any) string {
	switch a.Op {
	case "trust":
		if k, ok := data.(ssh.PublicKey); ok {
			return fmt.Sprintf("trust host key %s for %s", ssh.FingerprintSHA256(k), a.Name)
		}
	case "host-set":
		if a.Host != nil {
			return fmt.Sprintf("save host %s (%s@%s, profile %s, agent access %v)",
				a.Name, a.Host.User, a.Host.Addr(), a.Host.EffectiveProfile(), a.Host.Agent)
		}
	}
	return strings.TrimSpace("agentssh " + a.Op + " " + a.Name)
}
```

In `Unlock`, inside `if salt == nil {` before `KeyringGet`:

```go
		if s.d.osAuth() {
			if err := s.d.confirm("unlock the agentssh vault"); err != nil {
				return err
			}
		}
```

- [ ] **Step 7: Run tests**

Run: `go test -race ./internal/daemon/ ./internal/approval/`
Expected: PASS. Both `TestDaemonEndToEnd` (code mode, because CI has no polkit policy) and `TestOSAuth` pass.

If `TestDaemonEndToEnd` fails on a developer machine that has the polkit policy and a display, add `h.d.human = &humanok.Fake{Err: humanok.ErrUnavailable}` in `setup` right after `New` so that test stays in code mode.

- [ ] **Step 8: Commit**

```bash
git add internal/daemon internal/audit
git commit -m "feat(daemon): OS authentication for approvals and admin operations

Codes remain the fallback when no OS authentication is available.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: CLI flows, install-polkit, doctor, e2e and docs

**Files:**
- Modify: `internal/cli/cli.go` (register `install-polkit`, usage), `internal/cli/human.go` (`admin`, `cmdApprove`, `decideOne`, `cmdDoctor`, new `cmdInstallPolkit`)
- Create: `internal/humanok/e2efake.go`
- Modify: `scripts/e2e.py`, `.github/workflows/ci.yml`, `README.md`

**Interfaces:**
- Consumes: `BeginReply.OSAuth`, `StatusReply.Auth/AuthNote` (Task 6); `humanok.InstallPolicy` (Task 2).

- [ ] **Step 1: `admin()` without codes in OS mode**

In `internal/cli/human.go`, in `admin`, right after `a.Ticket = b.Ticket` insert:

```go
	if b.OSAuth {
		t.printf("confirm in the system authentication dialog…\n")
		var r daemon.AdminReply
		if err := c.Call("A.Admin", &a, &r); err != nil {
			return "", errf(1, "%v", err)
		}
		return r.Out, 0
	}
```

- [ ] **Step 2: `approve` without codes in OS mode; denials never ask for a code**

In `cmdApprove`, after `defer c.Close()` add:

```go
	var st daemon.StatusReply
	if err := c.Call("A.Status", &daemon.Empty{}, &st); err != nil {
		return callErr(err)
	}
	osAuth := st.Auth == "os"
```

and change the call `decideOne(t, c, r)` to `decideOne(t, c, r, osAuth)`.

Replace the `for { ... }` loop at the end of `decideOne` (and its signature) with:

```go
func decideOne(t *term, c interface {
	Call(string, any, any) error
}, r approval.Request, osAuth bool) {
```

(keep the printing lines unchanged), then:

```go
	for {
		choice := ""
		for choice == "" {
			switch a := strings.ToLower(t.prompt("[y] once  [s] same command 30 min  [n] deny  [m] deny with message: ")); a {
			case "y", "s", "n", "m":
				choice = a
			}
		}
		note, code := "", ""
		switch {
		case choice == "m":
			note = t.prompt("message for the agent: ")
		case choice == "n":
		case osAuth:
			t.printf("confirm in the system authentication dialog…\n")
		default:
			code = t.prompt("approval code (from the desktop notification): ")
		}
		err := c.Call("A.Decide", &daemon.DecideArgs{ID: r.ID, Code: code, Choice: choice, Note: note}, &daemon.Empty{})
		if err == nil {
			t.printf("#%d: %s\n", r.ID, map[string]string{"y": "approved once", "s": "approved for 30 minutes", "n": "denied", "m": "denied"}[choice])
			return
		}
		t.printf("%v\n", err)
		if !strings.Contains(err.Error(), "tries left") && !strings.Contains(err.Error(), "not confirmed") {
			return
		}
	}
}
```

- [ ] **Step 3: `install-polkit` and doctor**

In `internal/cli/human.go` add:

```go
func cmdInstallPolkit(args []string) int {
	if err := humanok.InstallPolicy(); err != nil {
		return errf(1, "%v", err)
	}
	fmt.Println("installed", humanok.PolicyPath, "— restart the daemon: systemctl --user restart agentssh")
	return 0
}
```

(import `"github.com/ASromancer/agentssh/internal/humanok"`). Register it in `internal/cli/cli.go` in the `cmds` map as `"install-polkit": cmdInstallPolkit,`. Add `install-polkit` to the human command list in `usage`, in the line `agentssh init [--passphrase] | unlock | lock | approve | reload | doctor | daemon`, which becomes `agentssh init [--passphrase] | unlock | lock | approve | reload | doctor | daemon | install-polkit`.

In `cmdDoctor`, inside the `else` branch after the `st.UserOnly` check:

```go
			if st.Auth == "os" {
				ok("approvals use OS authentication")
			} else {
				warn("approvals use codes from desktop notifications (" + st.AuthNote + ")")
			}
```

- [ ] **Step 4: e2e fake confirmer (build tag only)**

`internal/humanok/e2efake.go`:

```go
//go:build e2efake

package humanok

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Test-only confirmer: reads "allow" or "deny" from $AGENTSSH_E2E_HUMANOK
// and appends each dialog text to that file + ".log". Never in releases.
type platform struct{}

func (platform) Available() error {
	if os.Getenv("AGENTSSH_E2E_HUMANOK") == "" {
		return fmt.Errorf("%w: e2e fake not configured", ErrUnavailable)
	}
	return nil
}

func (platform) Confirm(_ context.Context, msg string) error {
	p := os.Getenv("AGENTSSH_E2E_HUMANOK")
	f, err := os.OpenFile(p+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		fmt.Fprintln(f, msg)
		f.Close()
	}
	b, _ := os.ReadFile(p)
	if strings.TrimSpace(string(b)) == "allow" {
		return nil
	}
	return ErrDenied
}
```

Check: `go build -tags e2efake -o /tmp/agentssh-fake . && go vet -tags e2efake ./internal/humanok/` passes; `go build . && go tool nm ./agentssh | grep -c e2e` prints `0` (the fake is not in normal builds).

- [ ] **Step 5: e2e scenario with the fake build**

In `scripts/e2e.py`, add to the top-level constants:

```python
FAKE_BIN = os.environ.get("E2E_FAKE_BIN")  # agentssh built with -tags e2efake
```

and, in `main()`, right before `os.kill(daemon_pid, signal.SIGTERM)` (the "daemon stops cleanly" block), insert:

```python
        if FAKE_BIN:
            os.kill(daemon_pid, signal.SIGTERM)
            time.sleep(0.5)
            gate = os.path.join(TMP, "humanok")
            open(gate, "w").write("deny")
            ENV["AGENTSSH_E2E_HUMANOK"] = gate
            out = subprocess.run([FAKE_BIN, "daemon", "--detach"], env=ENV, capture_output=True, text=True).stdout
            daemon_pid = int(re.search(r"pid (\d+)", out).group(1))
            for _ in range(50):
                if os.path.exists(ENV["AGENTSSH_SOCKET"]):
                    break
                time.sleep(0.1)
            t = Tty("unlock")
            t.expect("vault passphrase: ")
            t.send(PASS)
            t.wait()
            rc, out, _ = run("doctor")
            check("approvals use OS authentication" in out, "doctor reports OS authentication", out)
            victim4 = os.path.join(remote, "victim4")
            open(victim4, "w").write("x")
            agent = subprocess.Popen([BIN, "run", "e2e", f"rm {victim4}"], env=ENV, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            t = Tty("approve")
            t.expect(r"DESTRUCTIVE")
            t.expect(r"\[y\] once")
            t.send("y")
            t.expect("not confirmed")          # OS dialog refused
            open(gate, "w").write("allow")
            t.expect(r"\[y\] once")
            t.send("y")
            t.expect("approved once")
            out, err = agent.communicate(timeout=30)
            log = open(gate + ".log").read()
            check(agent.returncode == 0 and not os.path.exists(victim4) and f"rm {victim4}" in log,
                  "approve via OS authentication (no code), dialog shows the command", out + err + log)
            t.p.kill()
            t = Tty("key", "gen", "osauth")
            t.expect(r"ssh-ed25519 ")
            check(t.wait() == 0 and "key-gen osauth" in open(gate + ".log").read(), "admin op via OS authentication")
            ENV.pop("AGENTSSH_E2E_HUMANOK")
```

- [ ] **Step 6: Linux service: import the display environment**

Spike result (spec §4.6): polkit dialogs work from the systemd user service, so the service stays. For `Available()` to see the graphical session, in `internal/cli/os_unix.go` `installService`, `case "linux":`, add after the `enable --now` call:

```go
		// Let the daemon see the graphical session (humanok checks DISPLAY/WAYLAND_DISPLAY).
		_ = exec.Command("systemctl", "--user", "import-environment", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY").Run()
		_ = exec.Command("systemctl", "--user", "restart", "agentssh.service").Run()
```

- [ ] **Step 7: CI runs the fake e2e**

In `.github/workflows/ci.yml`, change the e2e step's `run:` to:

```yaml
        run: |
          command -v sshd || sudo apt-get install -y openssh-server
          go build -o "$RUNNER_TEMP/agentssh" .
          go build -tags e2efake -o "$RUNNER_TEMP/agentssh-fake" .
          E2E_FAKE_BIN="$RUNNER_TEMP/agentssh-fake" python3 scripts/e2e.py "$RUNNER_TEMP/agentssh"
```

- [ ] **Step 8: README**

In `README.md`:
- Replace the "## Approvals" section with a version that describes OS authentication first: polkit, Touch ID or the macOS password, the Windows password. It must also mention:
  - `sudo agentssh install-polkit` on Linux;
  - that codes remain the fallback;
  - that denials need no authentication.
- In "## Threat model", replace the bullet "If desktop notifications don't work…" with:

  > Approvals and admin operations are confirmed through the operating system's authentication dialog, triggered by the daemon itself; a caller of the daemon (including an agent) cannot complete them without the human passing that dialog. Without OS authentication (no graphical session, polkit action not installed), agentssh falls back to codes from desktop notifications, which a same-user process could read; `agentssh doctor` shows which mode is active.

- [ ] **Step 9: Full verification**

Run:

```bash
gofmt -l . && go vet ./... && GOOS=darwin go vet ./... && GOOS=windows go vet ./...
go test -race ./...
go build -o /tmp/agentssh-e2e/agentssh . && go build -tags e2efake -o /tmp/agentssh-e2e/agentssh-fake .
E2E_FAKE_BIN=/tmp/agentssh-e2e/agentssh-fake python3 scripts/e2e.py /tmp/agentssh-e2e/agentssh
```

Expected: no gofmt output, vet clean, all tests PASS, e2e ends with `all N checks passed` (N = 52 + 3).

- [ ] **Step 10: Manual checklist on this Linux desktop (with the user)**

After `sudo agentssh install-polkit` and `systemctl --user restart agentssh`:
1. `agentssh doctor` prints `ok    approvals use OS authentication`.
2. From a Claude Code session, run a destructive command on VMT_DWH (e.g. `rm /tmp/agentssh-check`, after the user creates that file). `agentssh approve` with `y` shows the polkit dialog containing the command; Cancel leaves it pending; the correct password runs it.
3. `agentssh host edit VMT_DWH --desc "..."` asks for the OS dialog, not a code.
4. From an `ssh localhost` session (no display), `agentssh doctor` reports code mode, and approve asks for a code.

Record outcomes in spec §4.5 (Linux). macOS and Windows manual checks are carried into plan B's release checklist.

- [ ] **Step 11: Commit and push**

```bash
git add -A
git commit -m "feat: OS-authenticated approve/admin flows, install-polkit, e2e and docs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin main
```

Expected: CI green on all three OSes, including `build-macos`.
