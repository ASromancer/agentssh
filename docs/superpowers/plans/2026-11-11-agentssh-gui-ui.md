# agentssh GUI Implementation Plan (plan B of 2: web UI, tray, clickable notifications)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An always-on GUI for agentssh: a local web UI served by the daemon (approvals, hosts, vault and keys, log and status), a tray icon with the pending count, and desktop notifications that open the approval page when clicked.

**Architecture:**
- `internal/ui` is an HTTP server on `127.0.0.1` with a random port. It has a per-start token that is exchanged for a cookie, checks the Host and Origin headers, and serves an embedded vanilla HTML/JS/CSS page.
- It calls the daemon's existing `Service` methods in-process through a small `Backend` interface, so every action still goes through plan A's OS authentication.
- `internal/tray` wraps `fyne.io/systray`.
- `internal/approval` notifications gain a link that opens the page.
- `cmdDaemon` wires everything together. On macOS the tray runs on the main goroutine.

**Tech Stack:** Go 1.26, stdlib `net/http` + `embed`, `fyne.io/systray` (the only new module), vanilla JS, no build step.

**Spec:** `docs/superpowers/specs/2026-11-11-agentssh-gui-design.md`, sections 5–8. Section 4 (OS authentication) is already implemented by plan A on branch `feat/os-auth`. This plan builds on branch `feat/gui`, which starts from `feat/os-auth`.

## Global Constraints

- Platforms: Linux, macOS, Windows; amd64 and arm64.
- Single binary; no frontend build step. HTML, JS and CSS are embedded with `embed`. No framework, no CDN, no inline `<script>`/`<style>` and no `style=` attributes, because CSP is `default-src 'self'`.
- The only new Go module is `fyne.io/systray`. cgo stays macOS-only, and Linux and Windows release builds stay `CGO_ENABLED=0`.
- The UI listens only on `127.0.0.1`. Every response carries `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`.
- The token is 32 random bytes in hex, generated anew at every start. The URL file `<state>/ui.url` has mode 0600. The cookie is named `agentssh` and is HttpOnly, SameSite=Strict, Path=/.
- Bad `Host` → 421. Missing or invalid cookie → 401. Non-GET without matching `Origin` → 403. Non-GET body that is not `application/json` → 415.
- No secret ever leaves the daemon through the UI. Only public keys and fingerprints are shown. Private-key export stays CLI-only. Passphrases are sent only over loopback and are never stored.
- Every state change goes through the existing daemon `Service` methods (Decide, Begin/Admin, Unlock, Lock), so plan A's OS authentication applies unchanged.
- UI text is in Vietnamese. Agent-controlled text (commands, notes, host names) is rendered with `textContent`, never `innerHTML`.
- Implementation subagents use the Sonnet model (user decision).
- Git: commit as `ASromancer <65549952+ASromancer@users.noreply.github.com>` (repo-local config already set); trailer per the implementing model's harness.
- Toolchain: `export PATH=$HOME/.local/sdk/go/bin:$PATH`.
- Every task's verification:
  - `gofmt -l .` prints nothing;
  - `go vet ./...` passes for `GOOS=linux`, `darwin` and `windows`, each with and without `-tags e2efake`;
  - `go test -race -count=1 ./...` passes.

## File Structure

| File | Responsibility |
|---|---|
| `internal/approval/approval.go` (modify) | `Notice{Title, Body, Link}`, `Queue.Notify func(Notice) error`, `Queue.Link`, `Desktop(Notice)` with clickable notifications |
| `internal/approval/notify.go`, `notify_e2efake.go` (modify) | `Notify(Notice)` |
| `internal/approval/open.go` (create) | `OpenURL`, `LocalURL` (loopback URLs only, trusted openers) |
| `internal/daemon/output.go` (create) | `ReadOutput` (moved from cli) |
| `internal/daemon/{daemon,service,rpc}.go` (modify) | `New(notify func(approval.Notice) error, …)`, `SetNotifyLink`, `Service()`, `HostList` RPC |
| `internal/sshconn/known.go` (create) | `Known(file, addr string) bool` |
| `internal/ui/server.go` (create) | `Options`, `Server`, `Start`, `URL`, `Link`, `Close`, guard middleware, static files |
| `internal/ui/api.go` (create) | JSON handlers and SSE `/events` |
| `internal/ui/backend.go` (create) | `Backend` interface, `ServiceBackend` adapter |
| `internal/ui/static/{index.html,app.js,app.css}` (create) | the page |
| `internal/tray/{tray.go,tray_stub.go,icon.go}` (create) | tray icon, menu, generated icon |
| `internal/cli/{human.go,cli.go,agent.go,mcp.go}` (modify) | daemon flags, UI and tray wiring, `agentssh ui`, doctor refactor, `ReadOutput` callers |
| `internal/hook/hook.go`, `internal/cli/install.go` (modify) | `ui` is human-only; Write/Edit judged by target path |
| `scripts/e2e.py`, `README.md` (modify) | UI e2e checks, docs |

---

### Task 1: Notices with links, clickable notifications, OpenURL

**Files:**
- Modify: `internal/approval/approval.go` (Queue, Add, Ticket, Desktop, windowsToast)
- Modify: `internal/approval/notify.go`, `internal/approval/notify_e2efake.go`
- Create: `internal/approval/open.go`, `internal/approval/open_test.go`
- Modify: `internal/approval/approval_test.go` (the `sink` helper)
- Modify: `internal/daemon/daemon.go` (`New` signature, `SetNotifyLink`), `internal/daemon/daemon_test.go` (harness notify)
- Check: `internal/cli/human.go` still compiles. `daemon.New(approval.Notify, …)` is unchanged at the call site, because `Notify` gets the new signature.

**Interfaces:**
- Produces:
  - `type approval.Notice struct{ Title, Body, Link string }`
  - `approval.NewQueue(notify func(Notice) error, timeout time.Duration) *Queue`
  - `Queue.Link func(id int) string`
  - `func approval.Notify(n Notice) error`
  - `func approval.Desktop(n Notice) error`
  - `func approval.OpenURL(u string) error`
  - `func approval.LocalURL(u string) bool`
  - `func linuxNotifyArgs(n Notice) []string` (unexported)
  - `daemon.New(notify func(approval.Notice) error, approvalTimeout time.Duration) (*Daemon, error)`
  - `func (d *Daemon) SetNotifyLink(f func(id int) string)`

- [ ] **Step 1: Write failing tests**

In `internal/approval/approval_test.go`, replace the `sink` type and its methods with:

```go
type sink struct{ last, link string }

func (s *sink) notify(n Notice) error { s.last, s.link = n.Body, n.Link; return nil }
func (s *sink) code() string          { return s.last[strings.LastIndex(s.last, " ")+1:] }
```

Every `NewQueue(func(_, _ string) error {…}, …)` literal in the test file becomes `NewQueue(func(Notice) error {…}, …)`. Fix each compile error the same way.

Append:

```go
func TestNoticeLink(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	q.Add(Request{ID: 3, Host: "web1", Cmd: "rm x", Level: "destructive"})
	if s.link != "" {
		t.Fatalf("link without Queue.Link: %q", s.link)
	}
	q.Link = func(id int) string { return fmt.Sprintf("http://127.0.0.1:1/#req=%d", id) }
	q.Add(Request{ID: 4, Host: "web1", Cmd: "rm y", Level: "destructive"})
	if s.link != "http://127.0.0.1:1/#req=4" {
		t.Fatalf("link %q", s.link)
	}
	q.Ticket("key-rm a", "", nil)
	if s.link != "" {
		t.Fatalf("admin notices carry no link: %q", s.link)
	}
}

func TestLinuxNotifyArgs(t *testing.T) {
	plain := linuxNotifyArgs(Notice{Title: "t", Body: "b"})
	if strings.Join(plain, " ") != "-u critical -a agentssh t b" {
		t.Fatalf("plain %q", plain)
	}
	linked := strings.Join(linuxNotifyArgs(Notice{Title: "t", Body: "b", Link: "http://127.0.0.1:9/"}), " ")
	if linked != "-u critical -a agentssh -A open=Mở --wait t b" {
		t.Fatalf("linked %q", linked)
	}
}
```

(add `"fmt"` to the test imports if missing). Note: `Ticket` only notifies in code mode. If the queue in this test is in OS mode (`UseCodes` returns false), set `q.UseCodes = func() bool { return true }` before the `Ticket` call so the assertion is meaningful.

`internal/approval/open_test.go`:

```go
package approval

import "testing"

func TestLocalURL(t *testing.T) {
	for u, want := range map[string]bool{
		"http://127.0.0.1:8123/?t=abc":     true,
		"http://localhost:8123/#req=4":     true,
		"https://127.0.0.1:8123/":          false,
		"http://example.com/":              false,
		"http://127.0.0.1.evil.com:80/":    false,
		"file:///etc/passwd":               false,
		"http://127.0.0.1:8123/\nrm -rf ~": false,
	} {
		if got := LocalURL(u); got != want {
			t.Errorf("LocalURL(%q) = %v", u, got)
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/approval/`
Expected: build failure: `undefined: Notice`, `undefined: linuxNotifyArgs`, `undefined: LocalURL`.

- [ ] **Step 3: Implement in `internal/approval/approval.go`**

Add the type near `Request`:

```go
// Notice is one desktop notification. Link, when set, is opened if the
// human clicks the notification (Linux and Windows).
type Notice struct{ Title, Body, Link string }
```

In `Queue`, change the field and add `Link`:

```go
	Notify func(Notice) error
	// Link returns the UI address of a request, shown as the notification's
	// click target. nil means no link. Set it before the queue is used.
	Link func(id int) string
```

Change `NewQueue`'s first parameter to `notify func(Notice) error`. In `Add`, replace the `q.Notify(...)` call with:

```go
	link := ""
	if q.Link != nil {
		link = q.Link(r.ID)
	}
	err := q.Notify(Notice{Title: "agentssh approval #" + fmt.Sprint(r.ID), Body: body, Link: link})
```

In `Ticket`, replace `q.Notify("agentssh", body)` with `q.Notify(Notice{Title: "agentssh", Body: body})`.

Replace `Desktop` with the following. Keep `notifyEnv` and the `windowsToast` constant; their existing definitions stay.

```go
// Desktop sends a desktop notification (notify-send / osascript /
// powershell). The helper is run only from a root-owned system path, never
// found through PATH; without one, Desktop fails and the code is shown in
// the terminal instead. A Link is opened when the human clicks the
// notification (Linux: notify-send action; Windows: toast launch).
func Desktop(n Notice) error {
	var cands []string
	switch runtime.GOOS {
	case "linux":
		cands = []string{"/usr/bin/notify-send", "/bin/notify-send"}
	case "darwin":
		cands = []string{"/usr/bin/osascript"}
	case "windows":
		cands = []string{filepath.Join(humanok.SystemDir(), "WindowsPowerShell", "v1.0", "powershell.exe")}
	default:
		return errors.New("desktop notifications not supported on " + runtime.GOOS)
	}
	bin, err := humanok.TrustedBinary(cands...)
	if err != nil {
		return err
	}
	if n.Link != "" && !LocalURL(n.Link) {
		n.Link = ""
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command(bin, linuxNotifyArgs(n)...)
	case "darwin":
		q := func(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
		cmd = exec.Command(bin, "-e", "display notification "+q(n.Body)+" with title "+q(n.Title))
	case "windows":
		// Title, body and link go through the environment, never into the script.
		cmd = exec.Command(bin, "-NoProfile", "-NonInteractive", "-Command", windowsToast)
	}
	cmd.Env = append(notifyEnv(os.Environ(), runtime.GOOS),
		"AGENTSSH_TITLE="+n.Title, "AGENTSSH_BODY="+n.Body, "AGENTSSH_LINK="+n.Link)
	if runtime.GOOS == "linux" && n.Link != "" {
		return waitForClick(cmd, n)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func linuxNotifyArgs(n Notice) []string {
	args := []string{"-u", "critical", "-a", "agentssh"}
	if n.Link != "" {
		args = append(args, "-A", "open=Mở", "--wait")
	}
	return append(args, n.Title, n.Body)
}

// waitForClick runs a notify-send that waits for its action. It returns
// once the notification is up; a later click on "Mở" opens the link. An
// old notify-send without -A/--wait fails at once: retry without the link.
func waitForClick(cmd *exec.Cmd, n Notice) error {
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return Desktop(Notice{Title: n.Title, Body: n.Body})
		}
		if strings.TrimSpace(out.String()) == "open" {
			_ = OpenURL(n.Link)
		}
		return nil
	case <-time.After(300 * time.Millisecond):
		go func() {
			if <-done == nil && strings.TrimSpace(out.String()) == "open" {
				_ = OpenURL(n.Link)
			}
		}()
		return nil
	}
}
```

(add `"bytes"` to the imports; `time` is already imported).

In `windowsToast`, insert this line before the `$app = ...` line:

```
if ($env:AGENTSSH_LINK) { $t.DocumentElement.SetAttribute('activationType', 'protocol'); $t.DocumentElement.SetAttribute('launch', $env:AGENTSSH_LINK) }
```

- [ ] **Step 4: `internal/approval/open.go`**

```go
package approval

import (
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ASromancer/agentssh/internal/humanok"
)

// LocalURL reports whether u is a plain http URL on this machine's
// loopback; only those are ever opened.
func LocalURL(u string) bool {
	if strings.ContainsAny(u, " \t\r\n") {
		return false
	}
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "http" {
		return false
	}
	h := p.Hostname()
	return h == "127.0.0.1" || h == "localhost"
}

// OpenURL opens a loopback URL in the user's browser with the platform's
// opener from a root-owned system path.
func OpenURL(u string) error {
	if !LocalURL(u) {
		return errors.New("refusing to open a non-local URL")
	}
	var bin string
	var args []string
	var err error
	switch runtime.GOOS {
	case "linux":
		bin, err = humanok.TrustedBinary("/usr/bin/xdg-open", "/bin/xdg-open")
		args = []string{u}
	case "darwin":
		bin, err = humanok.TrustedBinary("/usr/bin/open")
		args = []string{u}
	case "windows":
		bin, err = humanok.TrustedBinary(filepath.Join(humanok.SystemDir(), "rundll32.exe"))
		args = []string{"url.dll,FileProtocolHandler", u}
	default:
		return errors.New("cannot open a browser on " + runtime.GOOS)
	}
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = os.Environ() // the browser needs the user's full session
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}
```

- [ ] **Step 5: Notify functions**

`internal/approval/notify.go` body becomes:

```go
// Notify tells the human about a request or an admin code.
func Notify(n Notice) error { return Desktop(n) }
```

`internal/approval/notify_e2efake.go`: change the signature to `func Notify(n Notice) error` and write `fmt.Fprintf(f, "%s\t%s\t%s\n", n.Title, n.Body, n.Link)`.

- [ ] **Step 6: Daemon**

In `internal/daemon/daemon.go` change `New`'s first parameter to `notify func(approval.Notice) error`, and add:

```go
// SetNotifyLink makes approval notifications open f(id) when clicked.
// Call it before Serve.
func (d *Daemon) SetNotifyLink(f func(id int) string) { d.q.Link = f }
```

In `internal/daemon/daemon_test.go`, change the harness method to:

```go
func (h *harness) notify(n approval.Notice) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.notes = append(h.notes, n.Body)
	return nil
}
```

Fix any other test notify literal in the daemon package the same way (`func(approval.Notice) error`).

- [ ] **Step 7: Verify and commit**

Run the Global Constraints verification, then:

```bash
git add internal/approval internal/daemon
git commit -m "feat(approval): notifications carry a link; clicking opens the agentssh page"
```

---

### Task 2: Daemon support for the UI

**Files:**
- Create: `internal/daemon/output.go`, `internal/daemon/output_test.go`
- Create: `internal/sshconn/known.go`, `internal/sshconn/known_test.go`
- Modify: `internal/daemon/daemon.go` (`Service()`), `internal/daemon/rpc.go` (`HostListReply`), `internal/daemon/service.go` (`HostList`)
- Modify: `internal/cli/agent.go`, `internal/cli/mcp.go` (use `daemon.ReadOutput`; delete `readOutput`)
- Test: `internal/daemon/daemon_test.go` (HostList)

**Interfaces:**
- Consumes: Task 1's `daemon.New` signature.
- Produces:
  - `func daemon.ReadOutput(id int, grep, rng string) (string, error)`
  - `func (d *Daemon) Service() *Service`
  - `type daemon.HostListReply struct{ Hosts map[string]hosts.Host; Trusted map[string]bool }`
  - `func (s *Service) HostList(_ *Empty, r *HostListReply) error`
  - `func sshconn.Known(file, addr string) bool`

- [ ] **Step 1: Move `readOutput` to the daemon package**

Cut the function `readOutput` from `internal/cli/agent.go` and paste it into the new file `internal/daemon/output.go` (package `daemon`) as `ReadOutput`, keeping its body unchanged. Change only the name and the call to `daemon.OutPath(id)`, which becomes `OutPath(id)`. Give it the doc comment `// ReadOutput returns a stored output, optionally limited to a line range "a:b" (1-based, inclusive) and filtered by a regexp (with line numbers).` and the imports its body needs (`errors`, `fmt`, `os`, `regexp`, `strconv`, `strings`). Replace every `readOutput(` in `internal/cli` with `daemon.ReadOutput(` and remove the now-unused imports. `go build ./...` must pass.

`internal/daemon/output_test.go`:

```go
package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ASromancer/agentssh/internal/paths"
)

func TestReadOutput(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	os.MkdirAll(paths.Out(), 0o700)
	os.WriteFile(filepath.Join(paths.Out(), "7"), []byte("a\nerr one\nb\nerr two\n"), 0o600)
	if got, _ := ReadOutput(7, "^err", ""); got != "2: err one\n4: err two\n" {
		t.Fatalf("grep: %q", got)
	}
	if got, _ := ReadOutput(7, "", "2:3"); got != "err one\nb\n" {
		t.Fatalf("range: %q", got)
	}
	if _, err := ReadOutput(8, "", ""); err == nil {
		t.Fatal("missing id")
	}
}
```

- [ ] **Step 2: `sshconn.Known` (test first)**

`internal/sshconn/known_test.go`:

```go
package sshconn

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestKnown(t *testing.T) {
	f := filepath.Join(t.TempDir(), "known_hosts")
	if Known(f, "10.0.0.5:22") {
		t.Fatal("missing file counts as unknown")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	if err := Trust(f, "10.0.0.5:1611", k); err != nil {
		t.Fatal(err)
	}
	if !Known(f, "10.0.0.5:1611") || Known(f, "10.0.0.5:22") || Known(f, "10.0.0.6:1611") {
		t.Fatal("Known mismatch")
	}
}
```

`internal/sshconn/known.go`:

```go
package sshconn

import (
	"os"
	"strings"

	"golang.org/x/crypto/ssh/knownhosts"
)

// Known reports whether known_hosts has a key for addr (host:port).
func Known(file, addr string) bool {
	b, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	want := knownhosts.Normalize(addr)
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		for _, h := range strings.Split(f[0], ",") {
			if h == want {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 3: `Service()` and `HostList` (test first)**

Append to `TestDaemonEndToEnd` in `internal/daemon/daemon_test.go`, right after the `Hosts` check:

```go
	var hl HostListReply
	if err := h.call("HostList", &Empty{}, &hl); err != nil {
		t.Fatal(err)
	}
	if len(hl.Hosts) != 2 || hl.Hosts["hidden"].Agent || !hl.Hosts["web1"].Agent || !hl.Trusted["web1"] || hl.Trusted["hidden"] {
		t.Fatalf("host list: %+v", hl)
	}
	if h.d.Service() == nil {
		t.Fatal("Service accessor")
	}
```

`internal/daemon/rpc.go`:

```go
// HostListReply is every configured host (not only those visible to
// agents), for the human UI.
type HostListReply struct {
	Hosts   map[string]hosts.Host
	Trusted map[string]bool // host key pinned in known_hosts
}
```

`internal/daemon/daemon.go`:

```go
// Service returns the daemon's RPC service, for in-process callers (the UI).
func (d *Daemon) Service() *Service { return &Service{d} }
```

`internal/daemon/service.go`:

```go
func (s *Service) HostList(_ *Empty, r *HostListReply) error {
	cfg, _, _, _ := s.d.snapshot()
	r.Hosts, r.Trusted = map[string]hosts.Host{}, map[string]bool{}
	for name, h := range cfg.Hosts {
		r.Hosts[name] = *h
		r.Trusted[name] = sshconn.Known(paths.KnownHosts(), h.Addr())
	}
	return nil
}
```

- [ ] **Step 4: Verify and commit**

Run the Global Constraints verification, then:

```bash
git add internal/daemon internal/sshconn internal/cli
git commit -m "feat(daemon): host list, Service accessor and ReadOutput for the UI"
```

---

### Task 3: UI server core: token, cookie, Host/Origin guard, static files

**Files:**
- Create: `internal/ui/server.go`, `internal/ui/backend.go`, `internal/ui/api.go` (minimal; replaced in Task 4), `internal/ui/server_test.go`, `internal/ui/fake_test.go`
- Create: `internal/ui/static/index.html`, `internal/ui/static/app.js`, `internal/ui/static/app.css`. These start as minimal placeholders that Task 5 replaces; they must exist so `embed` compiles.

**Interfaces:**
- Consumes: `daemon.*` RPC types, `approval.Request`, Task 2's `daemon.HostListReply`.
- Produces:
  - `type ui.Check struct{ OK bool; Text string }`
  - `type ui.Options struct{ Backend Backend; Port int; URLFile string; Doctor func() []Check; Version string; AuditFile string }`
  - `func ui.Start(o Options) (*Server, error)`
  - `func (s *Server) URL() string`
  - `func (s *Server) Link(id int) string`
  - `func (s *Server) Close() error`
  - `type ui.Backend interface` (below)
  - `type ui.ServiceBackend struct{ S *daemon.Service }`
  - unexported `newServer(o Options, token string, port int) *Server` and `(*Server).handler() http.Handler` for tests

- [ ] **Step 1: `backend.go`**

```go
package ui

import (
	"github.com/ASromancer/agentssh/internal/approval"
	"github.com/ASromancer/agentssh/internal/daemon"
)

// Backend is what the UI needs from the daemon. ServiceBackend calls the
// daemon's RPC methods in-process, so plan A's OS authentication and every
// policy check apply exactly as for the CLI.
type Backend interface {
	Status() (daemon.StatusReply, error)
	Pending() ([]approval.Request, error)
	Decide(a daemon.DecideArgs) error
	HostList() (daemon.HostListReply, error)
	Begin(a daemon.BeginArgs) (daemon.BeginReply, error)
	Admin(a daemon.AdminArgs) (daemon.AdminReply, error)
	Unlock(pass string) error
	Lock() error
	Keys() ([]string, error)
}

type ServiceBackend struct{ S *daemon.Service }

func (b ServiceBackend) Status() (r daemon.StatusReply, err error) {
	err = b.S.Status(&daemon.Empty{}, &r)
	return
}
func (b ServiceBackend) Pending() (r []approval.Request, err error) {
	err = b.S.Pending(&daemon.Empty{}, &r)
	return
}
func (b ServiceBackend) Decide(a daemon.DecideArgs) error { return b.S.Decide(&a, &daemon.Empty{}) }
func (b ServiceBackend) HostList() (r daemon.HostListReply, err error) {
	err = b.S.HostList(&daemon.Empty{}, &r)
	return
}
func (b ServiceBackend) Begin(a daemon.BeginArgs) (r daemon.BeginReply, err error) {
	err = b.S.Begin(&a, &r)
	return
}
func (b ServiceBackend) Admin(a daemon.AdminArgs) (r daemon.AdminReply, err error) {
	err = b.S.Admin(&a, &r)
	return
}
func (b ServiceBackend) Unlock(pass string) error {
	return b.S.Unlock(&daemon.UnlockArgs{Pass: pass}, &daemon.Empty{})
}
func (b ServiceBackend) Lock() error { return b.S.Lock(&daemon.Empty{}, &daemon.Empty{}) }
func (b ServiceBackend) Keys() ([]string, error) {
	var r daemon.KeysReply
	err := b.S.Keys(&daemon.Empty{}, &r)
	return r.Keys, err
}
```

- [ ] **Step 2: Placeholder static files** (Task 5 replaces them)

`internal/ui/static/index.html`:

```html
<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><title>agentssh</title>
<link rel="stylesheet" href="/app.css"></head>
<body><main id="app">agentssh</main><script src="/app.js"></script></body></html>
```

`internal/ui/static/app.js`: `"use strict";`
`internal/ui/static/app.css`: `body { font-family: sans-serif; }`

- [ ] **Step 3: Write failing tests**

`internal/ui/fake_test.go` (shared with Task 4):

```go
package ui

import (
	"errors"
	"sync"

	"github.com/ASromancer/agentssh/internal/approval"
	"github.com/ASromancer/agentssh/internal/daemon"
	"github.com/ASromancer/agentssh/internal/hosts"
)

type fakeBackend struct {
	mu      sync.Mutex
	pending []approval.Request
	decided []daemon.DecideArgs
	admin   []daemon.AdminArgs
	locked  bool
	failAll bool
}

func (f *fakeBackend) Status() (daemon.StatusReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return daemon.StatusReply{Locked: f.locked, Pending: len(f.pending), Auth: "os"}, nil
}
func (f *fakeBackend) Pending() ([]approval.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]approval.Request{}, f.pending...), nil
}
func (f *fakeBackend) Decide(a daemon.DecideArgs) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll {
		return errors.New("not confirmed by the user")
	}
	f.decided = append(f.decided, a)
	return nil
}
func (f *fakeBackend) HostList() (daemon.HostListReply, error) {
	return daemon.HostListReply{Hosts: map[string]hosts.Host{"web1": {Host: "10.0.0.5", User: "deploy", Agent: true}},
		Trusted: map[string]bool{"web1": true}}, nil
}
func (f *fakeBackend) Begin(a daemon.BeginArgs) (daemon.BeginReply, error) {
	return daemon.BeginReply{Ticket: 77, OSAuth: true, Info: "info:" + a.Op}, nil
}
func (f *fakeBackend) Admin(a daemon.AdminArgs) (daemon.AdminReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.admin = append(f.admin, a)
	return daemon.AdminReply{Out: "done " + a.Op}, nil
}
func (f *fakeBackend) Unlock(pass string) error {
	if pass != "pw" {
		return errors.New("vault: wrong master key or passphrase")
	}
	f.mu.Lock()
	f.locked = false
	f.mu.Unlock()
	return nil
}
func (f *fakeBackend) Lock() error { f.mu.Lock(); f.locked = true; f.mu.Unlock(); return nil }
func (f *fakeBackend) Keys() ([]string, error) {
	return []string{"web1-agent\tssh-ed25519 SHA256:abc"}, nil
}
```

`internal/ui/server_test.go`:

```go
package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testTok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testServer() *Server {
	return newServer(Options{Backend: &fakeBackend{}}, testTok, 8123)
}

func do(t *testing.T, s *Server, method, target, host, origin, cookie, ctype, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "agentssh", Value: cookie})
	}
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

func TestGuard(t *testing.T) {
	s := testServer()
	const host, origin = "127.0.0.1:8123", "http://127.0.0.1:8123"

	w := do(t, s, "GET", "/?t="+testTok, host, "", "", "", "")
	if w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Fatalf("token exchange: %d %v", w.Code, w.Header())
	}
	c := w.Result().Cookies()
	if len(c) != 1 || c[0].Name != "agentssh" || c[0].Value != testTok || !c[0].HttpOnly || c[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie: %+v", c)
	}
	if w := do(t, s, "GET", "/?t=wrong", host, "", "", "", ""); w.Code != 401 {
		t.Fatalf("bad token: %d", w.Code)
	}
	if w := do(t, s, "GET", "/", host, "", "", "", ""); w.Code != 401 {
		t.Fatalf("no cookie: %d", w.Code)
	}
	if w := do(t, s, "GET", "/", "evil.example:8123", "", testTok, "", ""); w.Code != 421 {
		t.Fatalf("bad host: %d", w.Code)
	}
	if w := do(t, s, "GET", "/", "localhost:8123", "", testTok, "", ""); w.Code != 200 {
		t.Fatalf("localhost host: %d", w.Code)
	}
	w = do(t, s, "GET", "/", host, "", testTok, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/app.js") {
		t.Fatalf("index: %d %s", w.Code, w.Body.String())
	}
	for k, v := range map[string]string{
		"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY",
		"Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
	} {
		if w.Header().Get(k) != v {
			t.Errorf("header %s = %q", k, w.Header().Get(k))
		}
	}
	if w := do(t, s, "POST", "/api/lock", host, "", testTok, "application/json", "{}"); w.Code != 403 {
		t.Fatalf("post without origin: %d", w.Code)
	}
	if w := do(t, s, "POST", "/api/lock", host, "http://evil.example", testTok, "application/json", "{}"); w.Code != 403 {
		t.Fatalf("post foreign origin: %d", w.Code)
	}
	if w := do(t, s, "POST", "/api/lock", host, origin, testTok, "text/plain", "{}"); w.Code != 415 {
		t.Fatalf("post text/plain: %d", w.Code)
	}
	if w := do(t, s, "POST", "/api/lock", host, origin, testTok, "application/json", "{}"); w.Code != 200 {
		t.Fatalf("good post: %d", w.Code)
	}
}

func TestURL(t *testing.T) {
	s := testServer()
	if s.URL() != "http://127.0.0.1:8123/?t="+testTok || s.Link(9) != s.URL()+"#req=9" {
		t.Fatalf("%s %s", s.URL(), s.Link(9))
	}
}
```

- [ ] **Step 4: Run to verify failure**

Run: `go test ./internal/ui/`
Expected: build failure: `undefined: newServer`, `undefined: Options`.

- [ ] **Step 5: Implement `internal/ui/server.go`**

```go
// Package ui is agentssh's local web interface: approvals, hosts, vault and
// keys, log and status. It listens on 127.0.0.1 only. A per-start token is
// exchanged for an HttpOnly cookie, and Host and Origin are checked so
// other web pages and other local users cannot drive it. Every change still
// goes through the daemon, which asks the OS to authenticate the human.
package ui

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed static
var static embed.FS

type Check struct {
	OK   bool   `json:"ok"`
	Text string `json:"text"`
}

type Options struct {
	Backend   Backend
	Port      int            // 0 = random
	URLFile   string         // written with the tokenized URL (mode 0600), removed on Close
	Doctor    func() []Check // status checks shown in the UI
	Version   string
	AuditFile string // audit.jsonl to read for the log tab
}

type Server struct {
	opt   Options
	token string
	port  int
	srv   *http.Server
}

func newServer(o Options, token string, port int) *Server {
	return &Server{opt: o, token: token, port: port}
}

// Start listens on 127.0.0.1 and serves in the background.
func Start(o Options) (*Server, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.Port)))
	if err != nil {
		return nil, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		ln.Close()
		return nil, err
	}
	s := newServer(o, hex.EncodeToString(b), ln.Addr().(*net.TCPAddr).Port)
	s.srv = &http.Server{Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second}
	if o.URLFile != "" {
		if err := os.WriteFile(o.URLFile, []byte(s.URL()+"\n"), 0o600); err != nil {
			ln.Close()
			return nil, err
		}
	}
	go s.srv.Serve(ln)
	return s, nil
}

func (s *Server) hostport(h string) string { return h + ":" + strconv.Itoa(s.port) }

// URL is the address that logs a browser in (it carries the token).
func (s *Server) URL() string { return "http://" + s.hostport("127.0.0.1") + "/?t=" + s.token }

// Link opens the page on one approval request.
func (s *Server) Link(id int) string { return s.URL() + "#req=" + strconv.Itoa(id) }

func (s *Server) Close() error {
	if s.opt.URLFile != "" {
		os.Remove(s.opt.URLFile)
	}
	if s.srv == nil {
		return nil
	}
	return s.srv.Close()
}

func (s *Server) tokenOK(v string) bool {
	return len(v) == len(s.token) && subtle.ConstantTimeCompare([]byte(v), []byte(s.token)) == 1
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	sub, _ := fs.Sub(static, "static")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))
	return s.guard(mux)
}

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		if r.Host != s.hostport("127.0.0.1") && r.Host != s.hostport("localhost") {
			http.Error(w, "wrong host", http.StatusMisdirectedRequest)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/" && r.URL.Query().Has("t") {
			if !s.tokenOK(r.URL.Query().Get("t")) {
				http.Error(w, "this link is no longer valid; open agentssh from 'agentssh ui' or the tray icon", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "agentssh", Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if c, err := r.Cookie("agentssh"); err != nil || !s.tokenOK(c.Value) {
			http.Error(w, "open agentssh from 'agentssh ui' or the tray icon", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			o := r.Header.Get("Origin")
			if o != "http://"+s.hostport("127.0.0.1") && o != "http://"+s.hostport("localhost") {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				http.Error(w, "JSON only", http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
```

Create a minimal `internal/ui/api.go` so this task compiles. Task 4 replaces it.

```go
package ui

import "net/http"

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/lock", func(w http.ResponseWriter, r *http.Request) {
		if err := s.opt.Backend.Lock(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
	})
}
```

- [ ] **Step 6: Run tests, verify, commit**

Run the Global Constraints verification, then:

```bash
git add internal/ui
git commit -m "feat(ui): loopback server with token cookie, Host/Origin guard and security headers"
```

---

### Task 4: UI JSON API and live updates

**Files:**
- Replace: `internal/ui/api.go`
- Create: `internal/ui/api_test.go`

**Interfaces:**
- Consumes: Task 3 (`Server`, `Options`, `Backend`, `fakeBackend`, `do`, `testTok`), `daemon.ReadOutput`, `audit.Entry`.
- Produces HTTP endpoints, used by Task 5's JS and Task 7's e2e (all JSON; errors are `{"error": "..."}` with status 400):

| Method + path | Request | Response |
|---|---|---|
| GET `/api/status` | — | `{"status": StatusReply, "version": string}` |
| GET `/api/pending` | — | `[]approval.Request` |
| POST `/api/decide` | `{"id","choice","note","code"}` | `{}` |
| GET `/api/hosts` | — | `HostListReply` |
| POST `/api/admin/begin` | `{"op","name"}` | `BeginReply` |
| POST `/api/admin/commit` | `{"ticket","code","op","name","host","key","keyPassphrase","password"}` | `{"out": string}` |
| POST `/api/unlock` | `{"pass"}` | `{}` |
| POST `/api/lock` | `{}` | `{}` |
| GET `/api/keys` | — | `[]string` |
| GET `/api/audit` | `?host=&decision=&since=YYYY-MM-DD&limit=&offset=` | `{"entries": []audit.Entry, "total": int}`, newest first |
| GET `/api/out/{id}` | `?grep=&range=` | `{"text": string}` |
| GET `/api/doctor` | — | `[]Check` |
| GET `/events` | — | SSE stream; an `update` event whenever the pending ids, the lock state or the auth mode change, and a `: ping` comment every 15 s |

- [ ] **Step 1: Write failing tests** in `internal/ui/api_test.go`

```go
package ui

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ASromancer/agentssh/internal/approval"
	"github.com/ASromancer/agentssh/internal/paths"
)

const apiHost, apiOrigin = "127.0.0.1:8123", "http://127.0.0.1:8123"

func api(t *testing.T, s *Server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	ct := ""
	if method != "GET" {
		ct = "application/json"
	}
	return do(t, s, method, target, apiHost, apiOrigin, testTok, ct, body)
}

func TestAPIDecideAndAdmin(t *testing.T) {
	f := &fakeBackend{pending: []approval.Request{{ID: 5, Host: "web1", Cmd: "rm x", Level: "destructive"}}}
	s := newServer(Options{Backend: f, Version: "9.9"}, testTok, 8123)

	if w := api(t, s, "GET", "/api/pending", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"cmd":"rm x"`) {
		t.Fatalf("pending: %d %s", w.Code, w.Body.String())
	}
	if w := api(t, s, "POST", "/api/decide", `{"id":5,"choice":"y"}`); w.Code != 200 || len(f.decided) != 1 || f.decided[0].ID != 5 || f.decided[0].Choice != "y" {
		t.Fatalf("decide: %d %+v", w.Code, f.decided)
	}
	f.failAll = true
	if w := api(t, s, "POST", "/api/decide", `{"id":5,"choice":"y"}`); w.Code != 400 || !strings.Contains(w.Body.String(), "not confirmed") {
		t.Fatalf("decide error: %d %s", w.Code, w.Body.String())
	}
	if w := api(t, s, "GET", "/api/status", ""); !strings.Contains(w.Body.String(), `"version":"9.9"`) || !strings.Contains(w.Body.String(), `"Auth":"os"`) {
		t.Fatalf("status: %s", w.Body.String())
	}
	if w := api(t, s, "POST", "/api/admin/begin", `{"op":"trust","name":"web1"}`); !strings.Contains(w.Body.String(), `"Ticket":77`) {
		t.Fatalf("begin: %s", w.Body.String())
	}
	w := api(t, s, "POST", "/api/admin/commit", `{"ticket":77,"op":"host-set","name":"web2","host":{"host":"10.0.0.9","user":"root","agent":true}}`)
	if w.Code != 200 || len(f.admin) != 1 || f.admin[0].Host == nil || f.admin[0].Host.Host != "10.0.0.9" || f.admin[0].Ticket != 77 {
		t.Fatalf("commit host: %d %s %+v", w.Code, w.Body.String(), f.admin)
	}
	if w := api(t, s, "POST", "/api/unlock", `{"pass":"bad"}`); w.Code != 400 {
		t.Fatalf("unlock bad: %d", w.Code)
	}
	if w := api(t, s, "GET", "/api/hosts", ""); !strings.Contains(w.Body.String(), `"web1"`) {
		t.Fatalf("hosts: %s", w.Body.String())
	}
}

func TestAPIKeyImportConvertsEncryptedKey(t *testing.T) {
	f := &fakeBackend{}
	s := newServer(Options{Backend: f}, testTok, 8123)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "c", []byte("kp"))
	body, _ := json.Marshal(map[string]any{"ticket": 1, "op": "key-import", "name": "k", "key": string(pem.EncodeToMemory(block)), "keyPassphrase": "kp"})
	if w := api(t, s, "POST", "/api/admin/commit", string(body)); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if len(f.admin) != 1 {
		t.Fatal("no admin call")
	}
	if _, err := ssh.ParsePrivateKey(f.admin[0].PEM); err != nil {
		t.Fatalf("daemon received a key it cannot parse without passphrase: %v", err)
	}
	body, _ = json.Marshal(map[string]any{"ticket": 1, "op": "key-import", "name": "k", "key": string(pem.EncodeToMemory(block)), "keyPassphrase": "wrong"})
	if w := api(t, s, "POST", "/api/admin/commit", string(body)); w.Code != 400 {
		t.Fatalf("wrong passphrase accepted: %d", w.Code)
	}
}

func TestAPIAuditAndOutput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	auditFile := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(auditFile, []byte(strings.Join([]string{
		`{"time":"2026-11-10T10:00:00Z","id":1,"kind":"run","host":"web1","cmd":"ls","decision":"allow"}`,
		`{"time":"2026-11-11T10:00:00Z","id":2,"kind":"run","host":"db","cmd":"rm x","decision":"denied"}`,
		`{"time":"2026-11-11T11:00:00Z","id":3,"kind":"run","host":"web1","cmd":"df","decision":"allow"}`,
	}, "\n")+"\n"), 0o600)
	os.MkdirAll(paths.Out(), 0o700)
	os.WriteFile(filepath.Join(paths.Out(), "3"), []byte("x\nerror y\n"), 0o600)
	s := newServer(Options{Backend: &fakeBackend{}, AuditFile: auditFile}, testTok, 8123)

	var r struct {
		Entries []struct{ ID int } `json:"entries"`
		Total   int                `json:"total"`
	}
	json.Unmarshal(api(t, s, "GET", "/api/audit?host=web1", "").Body.Bytes(), &r)
	if r.Total != 2 || len(r.Entries) != 2 || r.Entries[0].ID != 3 {
		t.Fatalf("host filter, newest first: %+v", r)
	}
	json.Unmarshal(api(t, s, "GET", "/api/audit?since=2026-11-11&decision=denied", "").Body.Bytes(), &r)
	if r.Total != 1 || r.Entries[0].ID != 2 {
		t.Fatalf("since+decision: %+v", r)
	}
	json.Unmarshal(api(t, s, "GET", "/api/audit?limit=1&offset=1", "").Body.Bytes(), &r)
	if r.Total != 3 || len(r.Entries) != 1 || r.Entries[0].ID != 2 {
		t.Fatalf("paging: %+v", r)
	}
	if w := api(t, s, "GET", "/api/out/3?grep=error", ""); !strings.Contains(w.Body.String(), `2: error y`) {
		t.Fatalf("out: %s", w.Body.String())
	}
}

func TestEvents(t *testing.T) {
	f := &fakeBackend{}
	s := newServer(Options{Backend: f}, testTok, 8123)
	ts := httptest.NewServer(s.handler())
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/events", nil)
	req.Host = apiHost
	req.AddCookie(&http.Cookie{Name: "agentssh", Value: testTok})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	expect := func(want string) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case l := <-lines:
				if l == want {
					return
				}
			case <-deadline:
				t.Fatalf("no %q", want)
			}
		}
	}
	expect("event: update") // initial state
	f.mu.Lock()
	f.pending = []approval.Request{{ID: 8}}
	f.mu.Unlock()
	expect("event: update") // new pending request
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/ui/`
Expected: FAIL. The `/api/*` routes other than lock return 404 from the file server, and `/events` is missing.

- [ ] **Step 3: Implement `internal/ui/api.go`** (replace the whole file)

```go
package ui

import (
	"bufio"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ASromancer/agentssh/internal/audit"
	"github.com/ASromancer/agentssh/internal/daemon"
	"github.com/ASromancer/agentssh/internal/hosts"
)

const maxBody = 1 << 20

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(v); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return false
	}
	return true
}

func (s *Server) routes(mux *http.ServeMux) {
	b := s.opt.Backend
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := b.Status()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]any{"status": st, "version": s.opt.Version})
	})
	mux.HandleFunc("GET /api/pending", func(w http.ResponseWriter, r *http.Request) {
		p, err := b.Pending()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, p)
	})
	mux.HandleFunc("POST /api/decide", func(w http.ResponseWriter, r *http.Request) {
		var a struct {
			ID                 int
			Choice, Note, Code string
		}
		if !readJSON(w, r, &a) {
			return
		}
		if err := b.Decide(daemon.DecideArgs{ID: a.ID, Choice: a.Choice, Note: a.Note, Code: a.Code}); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("GET /api/hosts", func(w http.ResponseWriter, r *http.Request) {
		h, err := b.HostList()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, h)
	})
	mux.HandleFunc("POST /api/admin/begin", func(w http.ResponseWriter, r *http.Request) {
		var a daemon.BeginArgs
		if !readJSON(w, r, &a) {
			return
		}
		rep, err := b.Begin(a)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, rep)
	})
	mux.HandleFunc("POST /api/admin/commit", func(w http.ResponseWriter, r *http.Request) {
		var a struct {
			Ticket                       int
			Code, Op, Name               string
			Host                         *hosts.Host
			Key, KeyPassphrase, Password string
		}
		if !readJSON(w, r, &a) {
			return
		}
		args := daemon.AdminArgs{Ticket: a.Ticket, Code: a.Code, Op: a.Op, Name: a.Name, Host: a.Host}
		if a.Key != "" {
			p, err := normalizeKey([]byte(a.Key), a.KeyPassphrase, a.Name)
			if err != nil {
				fail(w, err)
				return
			}
			args.PEM = p
		}
		if a.Password != "" {
			args.Password = []byte(a.Password)
		}
		rep, err := b.Admin(args)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]string{"out": rep.Out})
	})
	mux.HandleFunc("POST /api/unlock", func(w http.ResponseWriter, r *http.Request) {
		var a struct{ Pass string }
		if !readJSON(w, r, &a) {
			return
		}
		if err := b.Unlock(a.Pass); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("POST /api/lock", func(w http.ResponseWriter, r *http.Request) {
		if err := b.Lock(); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("GET /api/keys", func(w http.ResponseWriter, r *http.Request) {
		k, err := b.Keys()
		if err != nil {
			fail(w, err)
			return
		}
		if k == nil {
			k = []string{}
		}
		writeJSON(w, k)
	})
	mux.HandleFunc("GET /api/audit", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))
		entries, total, err := readAudit(s.opt.AuditFile, q.Get("host"), q.Get("decision"), q.Get("since"), limit, offset)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]any{"entries": entries, "total": total})
	})
	mux.HandleFunc("GET /api/out/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			fail(w, errors.New("bad id"))
			return
		}
		text, err := daemon.ReadOutput(id, r.URL.Query().Get("grep"), r.URL.Query().Get("range"))
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]string{"text": text})
	})
	mux.HandleFunc("GET /api/doctor", func(w http.ResponseWriter, r *http.Request) {
		checks := []Check{}
		if s.opt.Doctor != nil {
			checks = s.opt.Doctor()
		}
		writeJSON(w, checks)
	})
	mux.HandleFunc("GET /events", s.events)
}

// normalizeKey turns an uploaded private key (possibly passphrase
// protected) into the unencrypted OpenSSH PEM the vault stores, like
// 'agentssh key import' does.
func normalizeKey(b []byte, passphrase, name string) ([]byte, error) {
	raw, err := ssh.ParseRawPrivateKey(b)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == "" {
			return nil, errors.New("this key is protected: enter its passphrase")
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(b, []byte(passphrase))
	}
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(raw, "agentssh-"+name)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// readAudit returns audit entries newest first, filtered and paged.
// ponytail: reads the whole file per request; index or tail-read if logs get huge.
func readAudit(path, host, decision, since string, limit, offset int) ([]audit.Entry, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var sinceT time.Time
	if since != "" {
		t, err := time.ParseInLocation("2006-01-02", since, time.Local)
		if err != nil {
			return nil, 0, errors.New("since must be YYYY-MM-DD")
		}
		sinceT = t
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []audit.Entry{}, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	var all []audit.Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var e audit.Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if (host != "" && e.Host != host) || (decision != "" && e.Decision != decision) || (!sinceT.IsZero() && e.Time.Before(sinceT)) {
			continue
		}
		all = append(all, e)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.After(all[j].Time) })
	total := len(all)
	if offset > total {
		offset = total
	}
	end := min(offset+limit, total)
	page := all[offset:end]
	if page == nil {
		page = []audit.Entry{}
	}
	return page, total, nil
}

// events streams "update" whenever pending requests, lock state or auth
// mode change, so the page refreshes without polling.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	last, idle := "", 0
	for {
		st, _ := s.opt.Backend.Status()
		p, _ := s.opt.Backend.Pending()
		ids := make([]string, len(p))
		for i, x := range p {
			ids[i] = strconv.Itoa(x.ID)
		}
		cur := fmt.Sprintf("%v|%s|%s", st.Locked, st.Auth, strings.Join(ids, ","))
		if cur != last {
			last, idle = cur, 0
			fmt.Fprintf(w, "event: update\ndata: %d\n\n", len(p))
			fl.Flush()
		} else if idle++; idle >= 15 {
			idle = 0
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
	}
}
```

- [ ] **Step 4: Verify and commit**

Run the Global Constraints verification (`go test -race` includes the SSE test), then:

```bash
git add internal/ui
git commit -m "feat(ui): JSON API for approvals, hosts, keys, audit and live updates"
```

---

### Task 5: The page (Vietnamese UI, 4 tabs)

**Files:**
- Replace: `internal/ui/static/index.html`, `internal/ui/static/app.js`, `internal/ui/static/app.css`
- Create: `internal/ui/static_test.go`

**Interfaces:**
- Consumes: the Task 4 endpoints exactly as listed in its table. JSON field names: `approval.Request` uses lowercase json tags (`id`, `host`, `cmd`, `level`, `reasons`, `kind`, `agent`, `user`, `cwd`, `repo`, `time`, `code`). `policy.Reason` uses `level`, `text`, `start`, `end`. `hosts.Host` uses `host`, `user`, `port`, `key`, `profile`, `agent`, `description`, `allow`, `deny`. `StatusReply`, `BeginReply` and `HostListReply` have no json tags, so their field names are capitalized (`Auth`, `Locked`, `Passphrase`, `Pending`, `Ticket`, `Info`, `Code`, `OSAuth`, `Hosts`, `Trusted`). `audit.Entry` uses lowercase json tags.
- Produces: no Go API.

- [ ] **Step 1: Write the failing static test** `internal/ui/static_test.go`

```go
package ui

import (
	"strings"
	"testing"
)

func TestStaticPage(t *testing.T) {
	s := testServer()
	page := do(t, s, "GET", "/", "127.0.0.1:8123", "", testTok, "", "").Body.String()
	for _, want := range []string{`<script src="/app.js"></script>`, `href="/app.css"`, `data-tab="approvals"`, `data-tab="hosts"`, `data-tab="vault"`, `data-tab="log"`} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}
	if strings.Contains(page, "<script>") || strings.Contains(page, "<style") || strings.Contains(page, "style=") || strings.Contains(page, "onclick=") {
		t.Error("inline script/style/handlers violate the CSP")
	}
	js := do(t, s, "GET", "/app.js", "127.0.0.1:8123", "", testTok, "", "").Body.String()
	for _, want := range []string{"/api/pending", "/api/decide", "/api/admin/begin", "/api/admin/commit", "/api/audit", "/events"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
	if strings.Contains(js, "innerHTML") {
		t.Error("app.js must build DOM with textContent, never innerHTML (agent-controlled text)")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/ui/ -run TestStaticPage`
Expected: FAIL (the placeholder page lacks the tabs and endpoints).

- [ ] **Step 3: `internal/ui/static/index.html`**

```html
<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agentssh</title>
<link rel="stylesheet" href="/app.css">
</head>
<body>
<header>
  <h1>agentssh</h1>
  <span id="authmode" class="badge"></span>
  <span id="vaultstate" class="badge"></span>
  <span id="version" class="muted"></span>
</header>
<nav>
  <button data-tab="approvals" class="tab active">Duyệt <span id="pendingcount" class="count"></span></button>
  <button data-tab="hosts" class="tab">Host</button>
  <button data-tab="vault" class="tab">Vault &amp; key</button>
  <button data-tab="log" class="tab">Nhật ký &amp; trạng thái</button>
</nav>
<div id="flash" class="flash hidden"></div>
<div id="configwarn" class="flash error hidden">Cấu hình trên đĩa (hosts.toml / rules.toml) đã thay đổi và chưa được duyệt: mọi yêu cầu của agent đang bị chặn. Kiểm tra lại thay đổi rồi bấm "Đọc lại cấu hình" ở tab Host.</div>
<main>
  <section id="approvals" class="panel">
    <p id="noreq" class="muted">Không có yêu cầu nào đang chờ.</p>
    <div id="reqlist"></div>
  </section>

  <section id="hosts" class="panel hidden">
    <div class="toolbar">
      <button id="hostadd">Thêm host</button>
      <button id="reload">Đọc lại cấu hình (reload)</button>
    </div>
    <table>
      <thead><tr><th>Tên</th><th>Địa chỉ</th><th>Profile</th><th>Agent</th><th>Key</th><th>Host key</th><th></th></tr></thead>
      <tbody id="hostrows"></tbody>
    </table>
    <form id="hostform" class="card hidden">
      <h2 id="hostformtitle">Thêm host</h2>
      <label>Tên <input name="name" required></label>
      <label>Địa chỉ <input name="host" required></label>
      <label>Port <input name="port" type="number" min="1" max="65535" value="22"></label>
      <label>User <input name="user"></label>
      <label>Key (tên trong vault) <select name="key"></select></label>
      <label>Profile <select name="profile"><option>readonly</option><option selected>standard</option><option>full</option></select></label>
      <label class="check"><input name="agent" type="checkbox"> Cho agent dùng</label>
      <label>Mô tả <input name="description"></label>
      <label>Allow (mỗi dòng một pattern) <textarea name="allow" rows="3"></textarea></label>
      <label>Deny (mỗi dòng một pattern) <textarea name="deny" rows="3"></textarea></label>
      <div class="toolbar"><button type="submit">Lưu</button><button type="button" id="hostcancel">Hủy</button></div>
    </form>
  </section>

  <section id="vault" class="panel hidden">
    <div class="card">
      <h2>Vault</h2>
      <p id="vaultinfo"></p>
      <div class="toolbar">
        <input id="unlockpass" type="password" placeholder="Passphrase (nếu có)" autocomplete="off">
        <button id="unlock">Mở khóa</button>
        <button id="lock">Khóa</button>
      </div>
    </div>
    <div class="card">
      <h2>Key</h2>
      <ul id="keylist" class="plain"></ul>
      <div class="toolbar">
        <input id="keyname" placeholder="Tên key mới">
        <button id="keygen">Tạo key ed25519</button>
      </div>
      <div class="toolbar">
        <input id="keyfile" type="file">
        <input id="keypass" type="password" placeholder="Passphrase của key (nếu có)" autocomplete="off">
        <button id="keyimport">Import key</button>
      </div>
      <div class="toolbar">
        <input id="pwname" placeholder="Tên mục mật khẩu">
        <input id="pwvalue" type="password" placeholder="Mật khẩu" autocomplete="off">
        <button id="pwimport">Lưu mật khẩu</button>
      </div>
      <pre id="pubkey" class="hidden"></pre>
      <button id="pubcopy" class="hidden">Copy public key</button>
    </div>
  </section>

  <section id="log" class="panel hidden">
    <div class="card"><h2>Trạng thái</h2><ul id="checks" class="plain"></ul></div>
    <div class="card">
      <h2>Nhật ký</h2>
      <div class="toolbar">
        <input id="fhost" placeholder="Host">
        <select id="fdecision"><option value="">Mọi quyết định</option><option>allow</option><option>approved</option><option>denied</option><option>forbidden</option><option>blocked</option><option>timeout</option><option>error</option></select>
        <input id="fsince" type="date">
        <button id="ffilter">Lọc</button>
      </div>
      <table>
        <thead><tr><th>Thời gian</th><th>#</th><th>Host</th><th>Mức</th><th>Quyết định</th><th>Exit</th><th>Lệnh</th></tr></thead>
        <tbody id="auditrows"></tbody>
      </table>
      <div class="toolbar"><button id="prev">‹ Mới hơn</button><span id="pageinfo" class="muted"></span><button id="next">Cũ hơn ›</button></div>
      <div id="outbox" class="card hidden">
        <h2 id="outtitle"></h2>
        <div class="toolbar"><input id="outgrep" placeholder="Lọc (regexp)"><button id="outfilter">Lọc</button><button id="outclose">Đóng</button></div>
        <pre id="outtext"></pre>
      </div>
    </div>
  </section>
</main>
<script src="/app.js"></script>
</body>
</html>
```

- [ ] **Step 4: `internal/ui/static/app.css`**

```css
:root { --bg: #f6f7f9; --fg: #1d2330; --muted: #6b7280; --card: #fff; --line: #e3e6eb; --red: #c62828; --green: #2e7d32; --accent: #1f5fbf; }
@media (prefers-color-scheme: dark) { :root { --bg: #14171c; --fg: #e8eaed; --muted: #9aa0a6; --card: #1d2128; --line: #2c313a; --red: #ef5350; --green: #66bb6a; --accent: #6ea8fe; } }
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.45 system-ui, sans-serif; background: var(--bg); color: var(--fg); }
header { display: flex; gap: .6rem; align-items: center; padding: .7rem 1rem; border-bottom: 1px solid var(--line); }
header h1 { font-size: 1.1rem; margin: 0 .6rem 0 0; }
nav { display: flex; gap: .3rem; padding: .5rem 1rem 0; border-bottom: 1px solid var(--line); }
.tab { border: 0; background: none; color: var(--fg); padding: .5rem .8rem; cursor: pointer; border-bottom: 2px solid transparent; }
.tab.active { border-bottom-color: var(--accent); font-weight: 600; }
main { padding: 1rem; max-width: 1100px; }
.hidden { display: none !important; }
.muted { color: var(--muted); }
.badge { font-size: .8rem; padding: .1rem .5rem; border-radius: 1rem; border: 1px solid var(--line); }
.count { background: var(--red); color: #fff; border-radius: 1rem; padding: 0 .45rem; font-size: .8rem; }
.count:empty { display: none; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: .5rem; padding: .8rem 1rem; margin-bottom: 1rem; }
.card h2 { font-size: 1rem; margin: 0 0 .6rem; }
.req.focus { outline: 2px solid var(--accent); }
.level { font-weight: 700; text-transform: uppercase; }
.level.destructive, .level.forbidden { color: var(--red); }
.cmd { font-family: ui-monospace, monospace; white-space: pre-wrap; word-break: break-all; background: var(--bg); padding: .5rem; border-radius: .3rem; }
.cmd mark { background: none; color: var(--red); font-weight: 700; text-decoration: underline; }
.meta { display: grid; grid-template-columns: 7rem 1fr; gap: .1rem .6rem; margin: .5rem 0; }
.toolbar { display: flex; gap: .4rem; align-items: center; flex-wrap: wrap; margin: .4rem 0; }
button { cursor: pointer; padding: .35rem .8rem; border-radius: .3rem; border: 1px solid var(--line); background: var(--card); color: var(--fg); }
button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
button.danger { color: var(--red); }
button:disabled { opacity: .5; cursor: wait; }
input, select, textarea { padding: .3rem .4rem; border: 1px solid var(--line); border-radius: .3rem; background: var(--card); color: var(--fg); font: inherit; }
label { display: grid; gap: .15rem; margin: .4rem 0; }
label.check { display: flex; align-items: center; gap: .4rem; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: .35rem .4rem; border-bottom: 1px solid var(--line); vertical-align: top; }
tbody tr.click { cursor: pointer; }
pre { white-space: pre-wrap; word-break: break-all; max-height: 30rem; overflow: auto; background: var(--bg); padding: .5rem; border-radius: .3rem; }
ul.plain { list-style: none; padding: 0; margin: 0; }
ul.plain li { padding: .2rem 0; }
.ok::before { content: "✔ "; color: var(--green); }
.warn::before { content: "⚠ "; color: var(--red); }
.flash { margin: .6rem 1rem 0; padding: .5rem .8rem; border-radius: .3rem; border: 1px solid var(--line); background: var(--card); }
.flash.error { border-color: var(--red); color: var(--red); }
```

- [ ] **Step 5: `internal/ui/static/app.js`**

```js
"use strict";
// agentssh UI. All text from the daemon (commands, host names, notes) is
// agent-controlled: render it with textContent only, never as HTML.

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
};
let status = null;
let auditOffset = 0;
const PAGE = 50;

async function call(method, path, body) {
  const opt = { method, headers: {} };
  if (method !== "GET") {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body || {});
  }
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function flash(msg, error) {
  const f = $("flash");
  f.textContent = msg;
  f.className = "flash" + (error ? " error" : "");
  clearTimeout(flash.t);
  flash.t = setTimeout(() => f.classList.add("hidden"), error ? 12000 : 5000);
}

async function busy(button, fn) {
  button.disabled = true;
  try { await fn(); } catch (e) { flash(e.message, true); } finally { button.disabled = false; }
}

// ---- tabs ----
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => showTab(t.dataset.tab)));
function showTab(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("hidden", p.id !== name));
  const run = (p) => p.catch((e) => flash(e.message, true));
  if (name === "hosts") run(loadHosts());
  if (name === "vault") run(loadVault());
  if (name === "log") { run(loadChecks()); run(loadAudit()); }
}

// ---- status ----
async function loadStatus() {
  const r = await call("GET", "/api/status");
  status = r.status;
  $("version").textContent = "v" + r.version;
  $("authmode").textContent = status.Auth === "os" ? "Xác thực hệ điều hành" : "Mã duyệt";
  $("vaultstate").textContent = status.Locked ? "Vault đang khóa" : "Vault đang mở";
  $("pendingcount").textContent = status.Pending ? String(status.Pending) : "";
  $("configwarn").classList.toggle("hidden", !status.UserOnly);
}

// ---- approvals ----
function highlighted(cmd, reasons) {
  const box = el("div", "cmd");
  const marks = new Array(cmd.length).fill(false);
  (reasons || []).forEach((r) => {
    if (r.level === "destructive" || r.level === "forbidden") {
      for (let i = Math.max(0, r.start); i < r.end && i < cmd.length; i++) marks[i] = true;
    }
  });
  let i = 0;
  while (i < cmd.length) {
    let j = i;
    while (j < cmd.length && marks[j] === marks[i]) j++;
    box.appendChild(marks[i] ? el("mark", null, cmd.slice(i, j)) : document.createTextNode(cmd.slice(i, j)));
    i = j;
  }
  return box;
}

function meta(rows) {
  const d = el("div", "meta");
  rows.forEach(([k, v]) => { d.appendChild(el("span", "muted", k)); d.appendChild(el("span", null, v || "-")); });
  return d;
}

async function loadPending() {
  const list = await call("GET", "/api/pending");
  const box = $("reqlist");
  box.replaceChildren();
  $("noreq").classList.toggle("hidden", list.length > 0);
  const focus = Number((location.hash.match(/req=(\d+)/) || [])[1]);
  list.forEach((r) => {
    const c = el("div", "card req" + (r.id === focus ? " focus" : ""));
    const h = el("h2");
    h.appendChild(el("span", "level " + r.level, r.level));
    h.appendChild(document.createTextNode(" #" + r.id + " — " + r.host));
    c.appendChild(h);
    c.appendChild(r.kind === "run" || r.kind === "job" ? highlighted(r.cmd, r.reasons) : el("div", "cmd", r.cmd));
    c.appendChild(meta([["Agent", r.agent], ["User", r.user], ["cwd", r.cwd], ["Repo", r.repo], ["Loại", r.kind], ["Lúc", new Date(r.time).toLocaleString()]]));
    const why = el("ul", "plain");
    (r.reasons || []).filter((x) => x.level !== "read").forEach((x) => why.appendChild(el("li", null, "[" + x.level + "] " + x.text)));
    c.appendChild(why);
    if (r.code) c.appendChild(el("p", "warn", "Không gửi được thông báo; mã duyệt: " + r.code));
    const bar = el("div", "toolbar");
    let code = null;
    if (status && status.Auth !== "os") {
      code = el("input"); code.placeholder = "Mã duyệt"; code.autocomplete = "off"; bar.appendChild(code);
    }
    const note = el("input"); note.placeholder = "Lời nhắn cho agent (khi từ chối kèm lời nhắn)";
    const mk = (label, cls, choice) => {
      const b = el("button", cls, label);
      b.addEventListener("click", () => busy(b, async () => {
        if (status && status.Auth === "os" && choice !== "n") flash("Hãy xác nhận trong hộp thoại của hệ điều hành…");
        await call("POST", "/api/decide", { id: r.id, choice, note: choice === "m" ? note.value : "", code: code ? code.value : "" });
        flash("#" + r.id + ": " + ({ y: "đã duyệt", s: "đã duyệt 30 phút", n: "đã từ chối", m: "đã từ chối kèm lời nhắn" })[choice]);
        refresh();
      }));
      return b;
    };
    bar.appendChild(mk("Duyệt 1 lần", "primary", "y"));
    bar.appendChild(mk("Duyệt 30 phút", null, "s"));
    bar.appendChild(mk("Từ chối", "danger", "n"));
    c.appendChild(bar);
    const bar2 = el("div", "toolbar");
    bar2.appendChild(note);
    bar2.appendChild(mk("Từ chối kèm lời nhắn", "danger", "m"));
    c.appendChild(bar2);
    box.appendChild(c);
    if (r.id === focus) c.scrollIntoView();
  });
}

// ---- admin helper: begin → (OS dialog or code) → commit ----
async function admin(op, name, extra) {
  const b = await call("POST", "/api/admin/begin", { op, name });
  let code = "";
  if (b.Info && !confirm(b.Info + "\n\nTiếp tục?")) return null;
  if (!b.OSAuth) {
    code = prompt((b.Code ? "Không gửi được thông báo; mã: " + b.Code + "\n" : "") + "Nhập mã duyệt từ thông báo:") || "";
    if (!code) return null;
  } else {
    flash("Hãy xác nhận trong hộp thoại của hệ điều hành…");
  }
  const r = await call("POST", "/api/admin/commit", Object.assign({ ticket: b.Ticket, code, op, name }, extra || {}));
  return r.out;
}

// ---- hosts ----
let hostData = { Hosts: {}, Trusted: {} };
async function loadHosts() {
  hostData = await call("GET", "/api/hosts");
  const rows = $("hostrows");
  rows.replaceChildren();
  Object.keys(hostData.Hosts).sort().forEach((name) => {
    const h = hostData.Hosts[name];
    const tr = el("tr");
    tr.appendChild(el("td", null, name));
    tr.appendChild(el("td", null, (h.user ? h.user + "@" : "") + h.host + ":" + (h.port || 22)));
    tr.appendChild(el("td", null, h.profile || "standard"));
    tr.appendChild(el("td", null, h.agent ? "có" : "không"));
    tr.appendChild(el("td", null, h.key || "-"));
    tr.appendChild(el("td", hostData.Trusted[name] ? "ok" : "warn", hostData.Trusted[name] ? "đã tin" : "chưa tin"));
    const td = el("td");
    const edit = el("button", null, "Sửa"); edit.addEventListener("click", () => openHostForm(name, h).catch((e) => flash(e.message, true)));
    const trust = el("button", null, "Trust"); trust.addEventListener("click", () => busy(trust, async () => { const o = await admin("trust", name); if (o) { flash(o); loadHosts(); } }));
    const del = el("button", "danger", "Xóa"); del.addEventListener("click", () => busy(del, async () => {
      if (!confirm("Xóa host " + name + "?")) return;
      const o = await admin("host-rm", name); if (o) { flash(o); loadHosts(); }
    }));
    td.append(edit, trust, del);
    tr.appendChild(td);
    rows.appendChild(tr);
  });
}

async function openHostForm(name, h) {
  const f = $("hostform");
  f.reset();
  $("hostformtitle").textContent = name ? "Sửa host " + name : "Thêm host";
  const keys = await call("GET", "/api/keys").catch(() => []);
  const sel = f.elements.key;
  sel.replaceChildren(el("option", null, ""));
  keys.forEach((k) => { const n = k.split("\t")[0]; const o = el("option", null, n); o.value = n; sel.appendChild(o); });
  f.elements.name.value = name || "";
  f.elements.name.readOnly = !!name;
  if (h) {
    f.elements.host.value = h.host || "";
    f.elements.port.value = h.port || 22;
    f.elements.user.value = h.user || "";
    sel.value = h.key || "";
    f.elements.profile.value = h.profile || "standard";
    f.elements.agent.checked = !!h.agent;
    f.elements.description.value = h.description || "";
    f.elements.allow.value = (h.allow || []).join("\n");
    f.elements.deny.value = (h.deny || []).join("\n");
  }
  f.classList.remove("hidden");
}

$("hostadd").addEventListener("click", () => openHostForm("", null).catch((e) => flash(e.message, true)));
$("hostcancel").addEventListener("click", () => $("hostform").classList.add("hidden"));
$("hostform").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const lines = (s) => s.split("\n").map((x) => x.trim()).filter(Boolean);
  const host = {
    host: f.elements.host.value.trim(), port: Number(f.elements.port.value) || 0, user: f.elements.user.value.trim(),
    key: f.elements.key.value, profile: f.elements.profile.value, agent: f.elements.agent.checked,
    description: f.elements.description.value.trim(), allow: lines(f.elements.allow.value), deny: lines(f.elements.deny.value),
  };
  busy(f.querySelector("button[type=submit]"), async () => {
    const o = await admin("host-set", f.elements.name.value.trim(), { host });
    if (o) { flash(o); f.classList.add("hidden"); loadHosts(); }
  });
});
$("reload").addEventListener("click", (e) => busy(e.target, async () => { const o = await admin("reload", ""); if (o) { flash(o); refresh(); } }));

// ---- vault & keys ----
async function loadVault() {
  await loadStatus();
  $("vaultinfo").textContent = (status.Locked ? "Đang khóa" : "Đang mở") + " — " + (status.Passphrase ? "dùng passphrase" : "dùng keyring của hệ điều hành");
  const list = $("keylist");
  list.replaceChildren();
  if (status.Locked) { list.appendChild(el("li", "muted", "Mở khóa vault để xem key.")); return; }
  const keys = await call("GET", "/api/keys");
  keys.forEach((k) => {
    const [name, info] = k.split("\t");
    const li = el("li", null, name + " — " + info + " ");
    const del = el("button", "danger", "Xóa");
    del.addEventListener("click", () => busy(del, async () => {
      if (!confirm("Xóa key " + name + "?")) return;
      const o = await admin("key-rm", name); if (o) { flash(o); loadVault(); }
    }));
    li.appendChild(del);
    list.appendChild(li);
  });
}
$("unlock").addEventListener("click", (e) => busy(e.target, async () => {
  if (!status.Passphrase) flash("Hãy xác nhận trong hộp thoại của hệ điều hành…");
  await call("POST", "/api/unlock", { pass: $("unlockpass").value });
  $("unlockpass").value = ""; flash("Đã mở khóa vault"); loadVault();
}));
$("lock").addEventListener("click", (e) => busy(e.target, async () => { await call("POST", "/api/lock"); flash("Đã khóa vault"); loadVault(); }));
$("keygen").addEventListener("click", (e) => busy(e.target, async () => {
  const name = $("keyname").value.trim(); if (!name) throw new Error("Nhập tên key");
  const pub = await admin("key-gen", name);
  if (!pub) return;
  $("pubkey").textContent = pub; $("pubkey").classList.remove("hidden"); $("pubcopy").classList.remove("hidden");
  flash("Đã tạo key. Thêm public key vào authorized_keys trên server."); loadVault();
}));
$("pubcopy").addEventListener("click", () => navigator.clipboard.writeText($("pubkey").textContent).then(() => flash("Đã copy")));
$("keyimport").addEventListener("click", (e) => busy(e.target, async () => {
  const name = $("keyname").value.trim(); const file = $("keyfile").files[0];
  if (!name || !file) throw new Error("Nhập tên key và chọn file");
  const o = await admin("key-import", name, { key: await file.text(), keyPassphrase: $("keypass").value });
  $("keypass").value = ""; $("keyfile").value = "";
  if (o) { flash(o); loadVault(); }
}));
$("pwimport").addEventListener("click", (e) => busy(e.target, async () => {
  const name = $("pwname").value.trim(); const pw = $("pwvalue").value;
  if (!name || !pw) throw new Error("Nhập tên và mật khẩu");
  const o = await admin("key-import", name, { password: pw });
  $("pwvalue").value = "";
  if (o) { flash(o); loadVault(); }
}));

// ---- log & status ----
async function loadChecks() {
  const checks = await call("GET", "/api/doctor");
  const ul = $("checks");
  ul.replaceChildren();
  checks.forEach((c) => ul.appendChild(el("li", c.ok ? "ok" : "warn", c.text)));
}
async function loadAudit() {
  const q = new URLSearchParams({ host: $("fhost").value.trim(), decision: $("fdecision").value, since: $("fsince").value, limit: PAGE, offset: auditOffset });
  const r = await call("GET", "/api/audit?" + q);
  const rows = $("auditrows");
  rows.replaceChildren();
  r.entries.forEach((e) => {
    const tr = el("tr", e.id ? "click" : "");
    [new Date(e.time).toLocaleString(), e.id || "", e.host, e.level, e.decision, e.exit === undefined ? "" : e.exit, e.cmd + (e.note ? " (" + e.note + ")" : "")]
      .forEach((v) => tr.appendChild(el("td", null, v)));
    if (e.id) tr.addEventListener("click", () => showOutput(e.id));
    rows.appendChild(tr);
  });
  $("pageinfo").textContent = r.total ? (auditOffset + 1) + "–" + Math.min(auditOffset + PAGE, r.total) + " / " + r.total : "Không có mục nào";
  $("prev").disabled = auditOffset === 0;
  $("next").disabled = auditOffset + PAGE >= r.total;
}
async function showOutput(id) {
  $("outbox").classList.remove("hidden");
  $("outtitle").textContent = "Output #" + id;
  $("outbox").dataset.id = id;
  const r = await call("GET", "/api/out/" + id + "?grep=" + encodeURIComponent($("outgrep").value)).catch((e) => ({ text: e.message }));
  $("outtext").textContent = r.text;
}
$("ffilter").addEventListener("click", () => { auditOffset = 0; loadAudit().catch((e) => flash(e.message, true)); });
$("prev").addEventListener("click", () => { auditOffset = Math.max(0, auditOffset - PAGE); loadAudit().catch((e) => flash(e.message, true)); });
$("next").addEventListener("click", () => { auditOffset += PAGE; loadAudit().catch((e) => flash(e.message, true)); });
$("outfilter").addEventListener("click", () => showOutput(Number($("outbox").dataset.id)));
$("outclose").addEventListener("click", () => $("outbox").classList.add("hidden"));

// ---- live updates ----
async function refresh() {
  try { await loadStatus(); await loadPending(); } catch (e) { flash(e.message, true); }
}
const es = new EventSource("/events");
es.addEventListener("update", refresh);
es.onerror = () => flash("Mất kết nối tới daemon agentssh", true);
refresh();
if (location.hash.startsWith("#req=")) showTab("approvals");
```

- [ ] **Step 6: Verify and commit**

Run `go test ./internal/ui/` (PASS), then the Global Constraints verification. Optionally load the page by hand: build, run `agentssh daemon --no-tray` with a temp HOME/XDG dirs, open the URL from the state dir's `ui.url`, and check the browser console for CSP errors. Say in the report whether you did this.

```bash
git add internal/ui/static internal/ui/static_test.go
git commit -m "feat(ui): approvals, hosts, vault and log pages (vanilla JS, CSP-clean)"
```

---

### Task 6: Tray icon

**Files:**
- Create: `internal/tray/tray.go` (build tag `linux || windows || (darwin && cgo)`), `internal/tray/tray_stub.go` (build tag `!(linux || windows || (darwin && cgo))`), `internal/tray/icon.go`, `internal/tray/tray_test.go`
- Modify: `go.mod`, `go.sum` (`fyne.io/systray`)

**Interfaces:**
- Produces:
  - `type tray.Options struct{ URL string; Pending func() int; Lock func() error; Open func(string) error }`
  - `func tray.Supported() bool`
  - `func tray.Run(o Options, done <-chan struct{})`, which blocks until `done` is closed and must be called from the main goroutine
  - `func tray.Title(n int) string`
  - `func tray.Icon(goos string) []byte`

- [ ] **Step 1: Add the module**

Run: `go get fyne.io/systray@latest`
Expected: go.mod lists `fyne.io/systray`. Do not run `go mod tidy` yet; it would drop the unused module. Run it in Step 6 after the code exists.

- [ ] **Step 2: Failing tests** `internal/tray/tray_test.go`

```go
package tray

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
)

func TestTitle(t *testing.T) {
	if Title(0) != "agentssh" || Title(3) != "agentssh: 3 yêu cầu chờ duyệt" {
		t.Fatalf("%q %q", Title(0), Title(3))
	}
}

func TestIcon(t *testing.T) {
	p := Icon("linux")
	img, err := png.Decode(bytes.NewReader(p))
	if err != nil || img.Bounds().Dx() != 32 || img.Bounds().Dy() != 32 {
		t.Fatalf("png: %v %v", err, img)
	}
	ico := Icon("windows")
	// ICONDIR: reserved 0, type 1, count 1; entry points at the PNG payload.
	if binary.LittleEndian.Uint16(ico[2:]) != 1 || binary.LittleEndian.Uint16(ico[4:]) != 1 {
		t.Fatalf("ico header % x", ico[:6])
	}
	size := binary.LittleEndian.Uint32(ico[14:])
	off := binary.LittleEndian.Uint32(ico[18:])
	if int(off+size) != len(ico) || !bytes.Equal(ico[off:], p) {
		t.Fatal("ico does not wrap the png")
	}
}
```

- [ ] **Step 3: `internal/tray/icon.go`** (no build tag)

```go
package tray

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
)

// Title is the tooltip, with the number of requests waiting.
func Title(n int) string {
	if n == 0 {
		return "agentssh"
	}
	return fmt.Sprintf("agentssh: %d yêu cầu chờ duyệt", n)
}

// Icon returns the tray icon: PNG, wrapped as ICO on Windows. It is drawn
// in code (a rounded blue square with a ">_" prompt), so there is no asset.
func Icon(goos string) []byte {
	const n = 32
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	bg := color.NRGBA{0x1f, 0x5f, 0xbf, 0xff}
	fg := color.NRGBA{0xff, 0xff, 0xff, 0xff}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := min(x, n-1-x), min(y, n-1-y) // rounded corners, radius 6
			if dx < 6 && dy < 6 && (6-dx)*(6-dx)+(6-dy)*(6-dy) > 36 {
				continue
			}
			img.Set(x, y, bg)
		}
	}
	for i := 0; i < 8; i++ { // ">"
		for w := 0; w < 3; w++ {
			img.Set(8+i+w, 8+i, fg)
			img.Set(8+i+w, 23-i, fg)
		}
	}
	for x := 17; x < 25; x++ { // "_"
		for w := 0; w < 3; w++ {
			img.Set(x, 21+w, fg)
		}
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	if goos != "windows" {
		return b.Bytes()
	}
	return icoWrap(b.Bytes(), n)
}

// icoWrap packs a PNG into a single-image ICO (Vista+ accepts PNG payloads).
func icoWrap(p []byte, size int) []byte {
	var b bytes.Buffer
	le := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
	le(uint16(0)) // reserved
	le(uint16(1)) // type: icon
	le(uint16(1)) // count
	b.WriteByte(byte(size))
	b.WriteByte(byte(size))
	b.WriteByte(0) // palette
	b.WriteByte(0) // reserved
	le(uint16(1))  // planes
	le(uint16(32)) // bpp
	le(uint32(len(p)))
	le(uint32(6 + 16)) // offset
	b.Write(p)
	return b.Bytes()
}
```

- [ ] **Step 4: `internal/tray/tray.go`**

```go
//go:build linux || windows || (darwin && cgo)

// Package tray shows agentssh in the system tray: the pending count, and a
// menu to open the UI, lock the vault or hide the icon.
package tray

import (
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"fyne.io/systray"
)

type Options struct {
	URL     string
	Pending func() int
	Lock    func() error
	Open    func(string) error
}

// Supported reports whether a tray can be shown in this session.
func Supported() bool {
	if runtime.GOOS == "linux" {
		return os.Getenv("DBUS_SESSION_BUS_ADDRESS") != ""
	}
	return true
}

// Run shows the tray until done is closed. It must run on the main
// goroutine (macOS). Hiding the icon keeps the daemon running.
func Run(o Options, done <-chan struct{}) {
	var once sync.Once
	quit := func() { once.Do(systray.Quit) }
	go func() { <-done; quit() }()
	systray.Run(func() {
		systray.SetIcon(Icon(runtime.GOOS))
		systray.SetTooltip(Title(0))
		open := systray.AddMenuItem("Mở agentssh", "Mở trang quản lý agentssh")
		lock := systray.AddMenuItem("Khóa vault", "Xóa key khỏi bộ nhớ daemon")
		systray.AddSeparator()
		hide := systray.AddMenuItem("Ẩn biểu tượng", "Ẩn tới lần khởi động sau")
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			last := -1
			for {
				select {
				case <-open.ClickedCh:
					_ = o.Open(o.URL)
				case <-lock.ClickedCh:
					_ = o.Lock()
				case <-hide.ClickedCh:
					quit()
					return
				case <-done:
					return
				case <-t.C:
					if n := o.Pending(); n != last {
						last = n
						systray.SetTooltip(Title(n))
						if runtime.GOOS == "darwin" {
							title := ""
							if n > 0 {
								title = strconv.Itoa(n)
							}
							systray.SetTitle(title)
						}
					}
				}
			}
		}()
	}, func() {})
	<-done
}
```

- [ ] **Step 5: `internal/tray/tray_stub.go`**

```go
//go:build !(linux || windows || (darwin && cgo))

package tray

type Options struct {
	URL     string
	Pending func() int
	Lock    func() error
	Open    func(string) error
}

func Supported() bool { return false }

func Run(o Options, done <-chan struct{}) { <-done }
```

- [ ] **Step 6: Verify and commit**

Run `go mod tidy`, `go test ./internal/tray/` (PASS) and the Global Constraints verification. Darwin vet runs with CGO off, so it uses the stub; the macOS cgo build is checked in CI. Also confirm `GOOS=linux CGO_ENABLED=0 go build ./...` and `GOOS=windows CGO_ENABLED=0 go build ./...` succeed, since the tray must not need cgo there.

```bash
git add go.mod go.sum internal/tray
git commit -m "feat(tray): tray icon with pending count, open UI, lock vault"
```

---

### Task 7: Wire it up: daemon flags, `agentssh ui`, doctor, hook, e2e, docs

**Files:**
- Modify: `internal/cli/human.go` (`cmdDaemon`, `cmdDoctor` → `doctorChecks`, new `cmdUI`)
- Modify: `internal/cli/cli.go` (register `ui`, usage)
- Modify: `internal/hook/hook.go` (`ui` human-only; Write/Edit judged by target path), `internal/hook/hook_test.go`
- Modify: `internal/cli/install.go` (`ui` in `humanOnlySubs`)
- Modify: `scripts/e2e.py`, `README.md`
- Test: `internal/cli/doctor_test.go` (add)

**Interfaces:**
- Consumes:
  - `ui.Start`, `ui.Options`, `ui.ServiceBackend`, `ui.Check`, `(*ui.Server).URL/Link/Close` (Tasks 3–4)
  - `tray.Supported/Run/Options` (Task 6)
  - `approval.OpenURL`, `approval.Notice` (Task 1)
  - `(*daemon.Daemon).Service/SetNotifyLink` (Tasks 1–2)
- Produces: `agentssh daemon [--no-ui] [--no-tray] [--ui-port N]` (plus `AGENTSSH_NO_TRAY=1`) and `agentssh ui`.

- [ ] **Step 1: Doctor refactor (test first)**

Add to `internal/cli/doctor_test.go` (adding the imports `path/filepath` and `strings` if they are missing):

```go
func TestDoctorChecksShape(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("AGENTSSH_SOCKET", filepath.Join(t.TempDir(), "none.sock"))
	checks := doctorChecks(false)
	if len(checks) == 0 || checks[0].OK || !strings.Contains(checks[0].Text, "daemon is not running") {
		t.Fatalf("%+v", checks)
	}
}
```

In `internal/cli/human.go`, move the body of `cmdDoctor` into a new function:

```go
// doctorChecks runs the doctor checks. notify=false skips sending the test
// notification (the UI calls this often).
func doctorChecks(notify bool) []ui.Check {
	var out []ui.Check
	ok := func(s string) { out = append(out, ui.Check{OK: true, Text: s}) }
	warn := func(s string) { out = append(out, ui.Check{OK: false, Text: s}) }
	// existing checks moved here unchanged (they already call ok/warn)
	return out
}
```

Move every existing check into it unchanged; they already call `ok(...)`/`warn(...)`. Remove the old `problems` counter from inside. Wrap the desktop-notification check in `if notify { … }`, and change its call to `approval.Desktop(approval.Notice{Title: "agentssh doctor", Body: "test notification"})`. After the vault checks, add:

```go
	if b, err := os.ReadFile(filepath.Join(paths.State(), "ui.url")); err == nil && len(b) > 0 {
		ok("UI is running (agentssh ui)")
	} else {
		warn("UI is not running (daemon started with --no-ui, or an older daemon)")
	}
```

Then:

```go
func cmdDoctor(args []string) int {
	problems := 0
	for _, c := range doctorChecks(true) {
		if c.OK {
			fmt.Println("ok    " + c.Text)
		} else {
			problems++
			fmt.Println("WARN  " + c.Text)
		}
	}
	if problems == 0 {
		fmt.Println("all good")
		return 0
	}
	return 1
}
```

- [ ] **Step 2: `cmdDaemon` wiring**

Replace `cmdDaemon` in `internal/cli/human.go`:

```go
func cmdDaemon(args []string) int {
	fs := newFlags("daemon")
	detach := fs.Bool("detach", false, "start the daemon in the background and return")
	logFile := fs.String("log", "", "append logs to this file")
	noUI := fs.Bool("no-ui", false, "do not serve the local web UI")
	noTray := fs.Bool("no-tray", false, "do not show the tray icon")
	uiPort := fs.Int("ui-port", 0, "UI port on 127.0.0.1 (0 = random)")
	if _, err := parse(fs, args); err != nil {
		return 2
	}
	*noTray = *noTray || os.Getenv("AGENTSSH_NO_TRAY") == "1"
	if *detach {
		if err := startDetached(filepath.Join(paths.State(), "daemon.log")); err != nil {
			return errf(1, "%v", err)
		}
		return 0
	}
	if *logFile != "" {
		os.MkdirAll(filepath.Dir(*logFile), 0o700)
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return errf(1, "%v", err)
		}
		log.SetOutput(f)
	}
	d, err := daemon.New(approval.Notify, approvalTimeout)
	if err != nil {
		return errf(1, "%v", err)
	}
	svc := d.Service()
	var srv *ui.Server
	if !*noUI {
		srv, err = ui.Start(ui.Options{
			Backend: ui.ServiceBackend{S: svc}, Port: *uiPort, Version: Version,
			URLFile: filepath.Join(paths.State(), "ui.url"), AuditFile: paths.Audit(),
			Doctor: func() []ui.Check { return doctorChecks(false) },
		})
		if err != nil {
			log.Printf("ui: %v (continuing without the UI)", err)
			srv = nil
		} else {
			defer srv.Close()
			d.SetNotifyLink(srv.Link)
			log.Printf("ui on %s", strings.SplitN(srv.URL(), "?", 2)[0])
		}
	}
	served := make(chan error, 1)
	stop := make(chan struct{})
	go func() { served <- d.Serve(); close(stop) }()
	if !*noTray && srv != nil && tray.Supported() {
		tray.Run(tray.Options{
			URL: srv.URL(), Open: approval.OpenURL,
			Lock: func() error { return svc.Lock(&daemon.Empty{}, &daemon.Empty{}) },
			Pending: func() int {
				var p []approval.Request
				svc.Pending(&daemon.Empty{}, &p)
				return len(p)
			},
		}, stop)
	}
	if err := <-served; err != nil {
		log.Print(err)
		return 1
	}
	return 0
}
```

Add the imports `github.com/ASromancer/agentssh/internal/ui` and `github.com/ASromancer/agentssh/internal/tray`, and `strings` if it is missing.

- [ ] **Step 3: `agentssh ui`**

```go
func cmdUI(args []string) int {
	b, err := os.ReadFile(filepath.Join(paths.State(), "ui.url"))
	u := strings.TrimSpace(string(b))
	if err != nil || u == "" {
		return errf(1, "the agentssh UI is not running (is the daemon up? started with --no-ui?)")
	}
	if err := approval.OpenURL(u); err != nil {
		fmt.Println("open this address in your browser:", u)
	}
	return 0
}
```

Register `"ui": cmdUI` in the `cmds` map in `internal/cli/cli.go`. Add `ui` to the human command list in `usage`.

- [ ] **Step 4: Hook changes (test first)**

In `internal/hook/hook_test.go` `TestBash`, add `{"agentssh ui", "deny"},`. In `TestEditWrite` (or a new test), add:

```go
	// Writing a document that merely mentions agentssh's paths is fine;
	// writing INTO them is not.
	doc := map[string]any{"file_path": filepath.Join(home, "work", "notes.md"),
		"content": "state lives in " + filepath.Join(home, ".config", "agentssh")}
	if got := run(t, "Write", doc); got != "" {
		t.Errorf("write mentioning agentssh paths: %q", got)
	}
```

Use the test file's existing `run` helper and `home` variable names; read the file first.

Then:
- add `"ui": true` to `humanOnly` in `internal/hook/hook.go`;
- add `"ui"` to `humanOnlySubs` in `internal/cli/install.go`;
- in `hook.Decide`, judge tools that name a target path by that path only. Scan the whole input only when the tool has no path field (e.g. Codex `apply_patch`):

```go
	hasPath := false
	for _, k := range []string{"file_path", "notebook_path", "path", "TargetFile", "AbsolutePath"} {
		if p, _ := input[k].(string); p != "" {
			hasPath = true
			if inside(p, cwd, protected) {
				return "deny", "agentssh config and state can only be changed by the user"
			}
		}
	}
	if !hasPath && mentions(fmt.Sprint(input), protected) { // fmt, not JSON: no escaped backslashes
		return "deny", "agentssh config and state can only be changed by the user"
	}
	return "", ""
```

(This replaces the existing loop and `mentions` check in `Decide`. The Codex `apply_patch` test must still deny.)

- [ ] **Step 5: e2e UI checks**

Read the header of `scripts/e2e.py` first; it documents the binary interface and the names of the notes file and fake gate.

Near the top, after `ENV` is built, add:

```python
import http.client
import urllib.parse

ENV["AGENTSSH_NO_TRAY"] = "1"


class UI:
    """Talks to the daemon's web UI like a browser would."""

    def __init__(self):
        url = open(os.path.join(HOME, ".local", "state", "agentssh", "ui.url")).read().strip()
        u = urllib.parse.urlsplit(url)
        self.host, self.port = u.hostname, u.port
        self.token = urllib.parse.parse_qs(u.query)["t"][0]
        self.cookie = None

    def req(self, method, path, body=None, host=None, origin="same", cookie=True, ctype="application/json"):
        c = http.client.HTTPConnection(self.host, self.port, timeout=30)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if cookie and self.cookie:
            h["Cookie"] = self.cookie
        data = None
        if method != "GET":
            h["Content-Type"] = ctype
            if origin == "same":
                h["Origin"] = f"http://127.0.0.1:{self.port}"
            elif origin:
                h["Origin"] = origin
            data = json.dumps(body or {})
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        return r.status, r.getheader("Set-Cookie"), r.read().decode()

    def login(self):
        status, setc, _ = self.req("GET", f"/?t={self.token}", cookie=False)
        self.cookie = setc.split(";")[0] if setc else None
        return status
```

In the OS-authentication (fake confirmer) section, right after the "doctor reports OS authentication" check, insert the block below. Adapt `gate`, `NOTES`, `remote` and the binary variable to the names the script uses.

```python
            ui = UI()
            check(ui.login() == 303 and ui.cookie and ui.cookie.startswith("agentssh="), "UI login exchanges the token for a cookie")
            check(ui.req("GET", "/api/pending", cookie=False)[0] == 401, "UI refuses requests without the cookie")
            check(ui.req("GET", "/api/pending", host="evil.example")[0] == 421, "UI refuses a foreign Host header")
            check(ui.req("POST", "/api/lock", origin="http://evil.example")[0] == 403, "UI refuses a cross-origin POST")
            st, _, body = ui.req("GET", "/api/hosts")
            check(st == 200 and '"e2e"' in body, "UI lists hosts", body)
            victim5 = os.path.join(remote, "victim5")
            open(victim5, "w").write("x")
            open(gate, "w").write("allow")
            agent = subprocess.Popen([BIN, "run", "e2e", f"rm {victim5}"], env=ENV, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            rid = None
            for _ in range(50):
                pend = json.loads(ui.req("GET", "/api/pending")[2])
                if pend:
                    rid = pend[0]["id"]
                    break
                time.sleep(0.2)
            st, _, body = ui.req("POST", "/api/decide", {"id": rid, "choice": "y"})
            out, err = agent.communicate(timeout=30)
            check(st == 200 and agent.returncode == 0 and not os.path.exists(victim5),
                  "approve from the UI (OS authentication) runs the command", body + out + err)
            st, _, body = ui.req("GET", "/api/audit?host=e2e&limit=5")
            check(st == 200 and f"rm {victim5}" in body, "UI shows the audit log", body)
            notes = open(NOTES).read()
            check(f"#req={rid}" in notes, "approval notification links to the UI request", notes[-300:])
```

- [ ] **Step 6: README**

Add a section `## GUI` after `## Approvals`:

```markdown
## GUI

The daemon serves a local page on `127.0.0.1` with a random port. Open it with `agentssh ui` or from the tray icon. Clicking an approval notification (Linux, Windows) opens it at that request.

- **Duyệt:** pending requests with the exact command (risky parts highlighted), approve once, approve 30 minutes, deny, or deny with a message. Approving shows the OS authentication dialog, as in the terminal.
- **Host:** add, edit, delete, trust a host key, reload the config.
- **Vault & key:** lock and unlock; generate, import and delete keys. Private keys are never shown; exporting stays in the terminal (`agentssh key export`).
- **Nhật ký & trạng thái:** the `doctor` checks and the audit log, with each command's full output.

The page needs a per-start token, which `agentssh ui` and the tray pass for you. It refuses other hosts and cross-origin requests, and everything it changes goes through the daemon's OS authentication. Flags: `agentssh daemon --no-ui`, `--no-tray`, `--ui-port N`. On GNOME the tray icon needs the AppIndicator extension (preinstalled on Ubuntu).
```

- [ ] **Step 7: Full verification and commit**

Run the Global Constraints verification and the e2e with the fake binary (see the e2e script header for the exact invocation). The e2e must end with `all N checks passed`, where N is the previous 57 plus the 9 new checks. Confirm the release-build marker check still prints 0. Then:

```bash
git add -A
git commit -m "feat: daemon serves the UI and tray; agentssh ui; doctor checks shared with the UI"
```

---

## Manual checklist (controller with the user, after Task 7)

1. Build and install on this Linux desktop:

   ```bash
   CGO_ENABLED=0 go build -o ~/.local/bin/agentssh .
   ```

   Then restart the agentssh user service yourself; the agent hook blocks the agent from doing it.
2. The tray icon appears (GNOME with AppIndicator). Its tooltip shows the pending count.
3. `agentssh ui` opens the page with no CSP errors in the browser console. Each tab loads.
4. Ask the agent for a destructive command on VMT_DWH. The notification shows "Mở"; clicking it opens the page at that request. "Duyệt 1 lần" shows the polkit dialog; Cancel shows an error and the request stays pending; the correct password runs it.
5. Host tab: edit the VMT_DWH description. The polkit dialog shows the save.
6. Vault tab: lock, then unlock. Log tab: filter by host, then open an output.
