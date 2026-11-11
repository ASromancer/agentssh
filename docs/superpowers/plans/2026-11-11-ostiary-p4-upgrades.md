# Ostiary P4: signed releases and upgrades. Implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ostiary users get new versions safely. Releases are signed with ed25519. `ostiary upgrade` and an "Cập nhật" button in the UI download a release, verify its signature, install it in the way that matches how Ostiary was installed, and restart the daemon.

**Architecture:**
- **`internal/update` package (pure, testable):** release lookup, semver comparison, signature verification over `SHA256SUMS`, install-kind detection, asset selection, archive extraction and in-place binary replacement.
- **`tools/sign`:** signs `SHA256SUMS` in CI with a key held in a GitHub secret.
- **Daemon:** checks for updates in the background and exposes the result in `Status`. It runs the upgrade as an approved admin op, then restarts itself. Under systemd or launchd it exits with code 75 and the service restarts it. Otherwise it spawns a successor that waits for the old process to exit.

**Tech Stack:** Go 1.26 stdlib only: `crypto/ed25519`, `crypto/sha256`, `net/http`, `archive/tar`, `archive/zip`, `compress/gzip`.

**Spec:** `docs/superpowers/specs/2026-11-11-ostiary-release-design.md` (§6, §7)

## Global Constraints

- **Signature:** a bad or missing signature, or a SHA256 mismatch, aborts the upgrade. There is no flag or environment variable that skips verification.
- **Network:** the only call is `GET {base}/repos/ASromancer/ostiary/releases/latest` (base `https://api.github.com`), plus downloads of that release's assets.
  - User-Agent: `ostiary/<version>`.
  - Timeout: 15 s for metadata, 5 min for downloads.
  - Download size cap: 200 MiB.
  - The base URL can be overridden only in `e2efake` builds, through `OSTIARY_E2E_RELEASES_URL`.
- **Background check:** first check 1 minute after the daemon starts, then every 24 h. It is turned off by `OSTIARY_NO_UPDATE_CHECK=1`. It never installs anything by itself.
- **Approval:** an upgrade from the UI is admin op `upgrade` (Begin→Admin, OS auth or code). `ostiary upgrade` is human-only, which is already in the hook.
- **`.deb` installs** are never self-replaced. The user is told the `apt` command to run instead.
- **Signing key:** the private key never enters the repo or logs. CI reads it only from the secret `OSTIARY_SIGNING_KEY` (base64 of the 32-byte ed25519 seed). The public key is embedded in `internal/update/pubkey.go`.
- **Housekeeping:**
  - No new dependencies. Do not edit `docs/`.
  - Commit as ASromancer. End each commit message with a blank line and then `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  - Do not push.
  - Run the full local checks after each task, the same set as P3. Tests use temp directories and `httptest` servers and never touch the real network or the user's install.

---

### Task 0 (controller, not an implementer): signing key

The controller does this before Task 1:

1. Generate an ed25519 key and write the seed (base64) to `~/.config/ostiary-release/signing.key` with mode 0600.
2. Set the repo secret `OSTIARY_SIGNING_KEY` through the GitHub API. Encrypt the value as a libsodium sealed box against the repo's Actions public key, using a throwaway Go program with `golang.org/x/crypto/nacl/box` that lives outside the repo.
3. Hand Task 1 the public key in base64.

---

### Task 1: `internal/update` core + `tools/sign`

**Files:**
- Create: `internal/update/update.go`, `internal/update/pubkey.go`, `internal/update/update_test.go`
- Create: `tools/sign/main.go`

**Interfaces:**
- Produces, in package `update`:

```go
var PublicKey ed25519.PublicKey // from pubkey.go (base64 constant decoded at init)

type Release struct {
	Version string            // "0.3.0" (tag without "v")
	URL     string            // html_url
	Notes   string            // body, trimmed to 2000 bytes
	Assets  map[string]string // asset name -> browser_download_url
}

type Kind int

const (
	Standalone Kind = iota // a bare binary the user can overwrite
	WindowsInstaller       // installed by Ostiary-Setup (unins000.exe next to the exe)
	MacApp                 // inside Ostiary.app/Contents/MacOS
	Deb                    // /usr/bin/ostiary from the .deb
)

func Latest(ctx context.Context, base, current string) (*Release, error) // base "" = https://api.github.com
func Newer(a, b string) bool                       // semver: is a newer than b ("dev"/"0.0.0-dev.x" is older than anything)
func Verify(sums, sig []byte, pub ed25519.PublicKey) error
func SumFor(sums []byte, name string) (string, error) // hex sha256 for an asset name
func DetectKind(exe, goos string) Kind
func AssetName(k Kind, goos, goarch, version string) string
func Apply(ctx context.Context, r *Release, k Kind, exe, goos, goarch string, client *http.Client) (msg string, err error)
```

`Apply` does the following:
1. Downloads `SHA256SUMS` and `SHA256SUMS.sig` and runs `Verify`.
2. Downloads the asset and checks its sum with `SumFor`.
3. Acts according to the install kind:
   - **Standalone or MacApp:** extracts `ostiary` (or `ostiary.exe` and `ostiary-app.exe` on Windows) into temp files in the exe's directory with mode 0755, then renames them over the old ones. On Windows, it first renames each running exe to `<name>.old`.
   - **WindowsInstaller:** saves the setup file to a temp path and starts it detached with `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`. In that case `msg` says the installer is running.
   - **Deb:** returns an error before downloading anything. The error message holds the command `sudo apt install ./ostiary_<ver>_<arch>.deb` and the asset URL.
- `tools/sign`: `OSTIARY_SIGNING_KEY=<b64 seed> go run ./tools/sign FILE` writes `FILE.sig` (base64 signature plus a newline). It exits with a non-zero code if the env var is empty.

- [ ] **Step 1: Tests first**

`update_test.go` covers the following. It uses `httptest.NewServer` serving a fake `releases/latest` JSON, plus assets built in the test: a tar.gz holding `ostiary`, `SHA256SUMS` and a signature made with a key generated in the test.

- `Newer`:
  - `Newer("0.3.0","0.2.9")` is true;
  - `Newer("0.2.0","0.2.0")` is false;
  - `Newer("0.10.0","0.9.1")` is true;
  - `Newer("0.2.0","dev")` is true;
  - `Newer("0.2.0","0.0.0-dev.abc")` is true;
  - `Newer("0.2.0-rc1","0.2.0")` is false.
- `Verify`:
  - a good signature passes;
  - a flipped byte in sums fails;
  - an empty sig fails;
  - another key fails.
- `SumFor`:
  - finds the line `<hex>  <name>`;
  - an unknown name returns an error.
- `DetectKind`:
  - `/Applications/Ostiary.app/Contents/MacOS/ostiary` on darwin gives `MacApp`;
  - `/usr/bin/ostiary` on linux gives `Deb`;
  - `/home/u/bin/ostiary` gives `Standalone`;
  - a Windows temp dir containing `unins000.exe` plus the exe gives `WindowsInstaller`. Create the files in `t.TempDir()`. `DetectKind` only checks for files, so this test runs on any OS.
- `AssetName` covers each kind, OS and arch, following the P3 names:
  - `ostiary-linux-amd64.tar.gz`;
  - `ostiary-windows-amd64.zip`;
  - `ostiary-darwin-universal.tar.gz`;
  - `Ostiary-Setup-0.3.0-x64.exe`;
  - `ostiary_0.3.0_amd64.deb`.
- `Latest` against the fake server parses `tag_name`, `html_url`, `body` and `assets[].name/browser_download_url`.
- `Apply` (`Standalone`, linux) replaces the file at `exe` in a temp dir with the new bytes, mode 0755.
- `Apply` with a tampered asset (sum mismatch) leaves `exe` untouched and returns an error.
- `Apply` with a bad signature returns an error and downloads no asset. The fake server counts requests to check this.

Run the tests. They should fail because nothing is implemented yet.

- [ ] **Step 2: Implement `update.go`, `pubkey.go`, `tools/sign`**

`pubkey.go` holds `const publicKeyB64 = "<from Task 0>"`, decoded in `init` into `PublicKey`. A bad constant panics, and a test asserts that it decodes to 32 bytes.

Download hardening:
- use `io.LimitReader(resp.Body, 200<<20)`;
- the status code must be 200;
- an asset URL must start with `https://github.com/ASromancer/ostiary/releases/download/` or `https://objects.githubusercontent.com/`, unless base was overridden in tests. In that case, allow the test server's host only.

Pass `allowHosts []string` internally so the tests can inject it.

- [ ] **Step 3: Verify, commit**

```bash
git add internal/update tools/sign
git commit -m "feat(update): signed release lookup, verification, install-kind aware apply; tools/sign

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `ostiary upgrade`, daemon update check, `upgrade` admin op, restart

**Files:**
- Create: `internal/cli/upgrade.go`, `internal/cli/upgrade_test.go`
- Modify: `internal/cli/cli.go` (register `upgrade`; on start, delete leftover `*.old` next to the exe on Windows, best effort)
- Create: `internal/daemon/update.go` (background check, `SetVersion`, restart logic, `Restart` RPC)
- Modify: `internal/daemon/rpc.go` (`StatusReply.Update *UpdateInfo`), `internal/daemon/service.go` (`Status` fills `Update`), `internal/daemon/admin.go` (op `upgrade`)
- Modify: `internal/cli/human.go` (`cmdDaemon`: `SetVersion(Version)`, exit code 75 on restart request, `--after-pid`)
- Modify: `packaging/windows/ostiary.iss` (relaunch after a silent install)
- Modify: `scripts/e2e.py` (+1 check: `upgrade --check` against a fake release server)
- Test: `internal/daemon/update_test.go`

**Interfaces:**
- Consumes: everything from Task 1.
- Produces:

```go
type UpdateInfo struct {
	Version, URL, Notes string
	Manual             string // non-empty for .deb: the command the user must run
}
func (d *Daemon) SetVersion(v string)
func (s *Service) Restart(_ *Empty, _ *Empty) error // humans only via the CLI; replies, then restarts
```

- Admin op `upgrade`, whose Name is the target version.
  - `Begin` fails unless `d.update` is non-nil and `Name == d.update.Version`.
  - `Admin` runs `update.Apply`, puts the message in `r.Out`, and schedules a restart 1 s later, except for `Deb`, which returns an error carrying the manual instructions.
  - `adminMessage`: `upgrade Ostiary from <cur> to <ver> (signature verified before install)`.
- Restart routine, `d.restart()`:
  - If `INVOCATION_ID` is set (systemd) or `XPC_SERVICE_NAME` contains `dev.ostiary` (launchd), it closes the listener and makes `cmdDaemon` exit 75.
  - Otherwise it starts the successor `<exe> daemon --detach --after-pid <pid>` plus the original detach flags, then closes the listener, and `cmdDaemon` exits 0.
  - With `--after-pid N`, the daemon waits up to 10 s for process N to exit before it calls `Listen`. Poll `daemon.Running()` until it is false and the socket is free.
- The systemd unit already has `Restart=on-failure`, so exit 75 is restarted. Check that the launchd plist has `KeepAlive` true; it does.
- `ostiary upgrade [--check] [--yes]`:
  1. Prints the current and latest version.
  2. With `--check`, stops there: exit 0 when up to date, exit 10 when an update exists (scriptable).
  3. Otherwise asks for confirmation through `openTTY`, unless `--yes` is given. `--yes` still requires a human, because the hook blocks agents.
  4. Runs `Apply`.
  5. If a daemon is running, calls the `Restart` RPC.
  6. Prints the result.
- `.iss` gets a new `[Run]` line, `Filename: "{app}\ostiary-app.exe"; Parameters: "daemon --detach"; Flags: runhidden nowait; Check: WizardSilent`. A silent upgrade then brings the daemon back.

- [ ] **Step 1: Tests first**

- Daemon:
  - With a fake release server (base injected via an unexported field or an option, never the real network) and `SetVersion("0.1.0")`, a manual `d.checkUpdate()` fills `Status.Update`.
  - Once `SetVersion` equals the latest version, `Update` is nil.
  - `Begin` `upgrade` with a wrong version fails.
- `OSTIARY_NO_UPDATE_CHECK=1` means the background loop never starts. Expose the decision as a pure function `updateCheckEnabled(env func(string) string) bool` and test that.
- CLI: `upgrade --check` against a fake server returns 10 when newer and 0 when equal. Inject the base in tests with a package variable that only tests set.
- e2e (`scripts/e2e.py`):
  - Start a tiny local HTTP server in Python serving `releases/latest` with a version higher than the binary's.
  - Set `OSTIARY_E2E_RELEASES_URL` to it.
  - Run `upgrade --check` and expect exit 10 plus the new version in stdout.
  - The e2efake build honours the env var. Release builds must not: put the override behind the `e2efake` build tag, like the other e2e hooks, so the CI marker check still passes.

- [ ] **Step 2: Implement**

- [ ] **Step 3: Verify (e2e now 71 checks), commit**

```bash
git add -A
git commit -m "feat: ostiary upgrade, background update check, approved upgrade from the UI, self-restart

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: UI update banner + CI signing

**Files:**
- Modify: `internal/ui/static/index.html`, `app.js`, `app.css` (update banner)
- Modify: `.github/workflows/ci.yml` (sign `SHA256SUMS` on tags)
- Modify: `README.md` (an "Upgrading" section)

**Interfaces:**
- Consumes: `Status.Update {Version, URL, Notes, Manual}` and admin op `upgrade`.

- [ ] **Step 1: Banner**

When `status.Update` is set, show `#updatebanner`, styled like `#configwarn` but with the info/accent colour. It contains:
- the text `Có bản Ostiary <Version>`;
- a button "Cập nhật", which runs `admin("upgrade", Version)`, then toasts the output and shows a wait layer: "Ostiary đang khởi động lại…". The SSE reconnect (`es.onopen` → refresh) clears the wait layer;
- a link "Xem thay đổi" with `href` set to `URL`, `target=_blank` and `rel=noopener noreferrer`. Set `href` only if `URL` starts with `https://github.com/ASromancer/ostiary/`;
- when `Manual` is non-empty, no button. Instead, a monospace block holding `Manual`, with `copyBtn`.

Release notes are not rendered; the GitHub page shows them. Every string is set with `textContent`.

- [ ] **Step 2: CI signing**

In the `release` job, after `sha256sum`, and only on `refs/tags/v*`:

```yaml
      - if: startsWith(github.ref, 'refs/tags/v')
        uses: actions/setup-go@v5
        with: { go-version-file: go.mod }
      - if: startsWith(github.ref, 'refs/tags/v')
        env: { OSTIARY_SIGNING_KEY: "${{ secrets.OSTIARY_SIGNING_KEY }}" }
        run: |
          go run ./tools/sign dist/SHA256SUMS
          go run ./tools/sign -verify dist/SHA256SUMS   # checks with the embedded public key
```

(The release job needs `actions/checkout` for `go run`; add it.) Add `-verify` mode to `tools/sign`: it checks `FILE.sig` against `update.PublicKey` and exits non-zero on mismatch. This catches a secret and an embedded key that do not belong together.

- [ ] **Step 3: README "Upgrading"**

Explain the following:
- the banner and `ostiary upgrade`;
- what is verified (the signature over `SHA256SUMS`, then the asset's hash);
- `.deb` users run `apt install` with the new `.deb`;
- `OSTIARY_NO_UPDATE_CHECK=1`;
- the passphrase-mode vault needs unlocking after the restart.

- [ ] **Step 4: Verify, screenshots of the banner (light/dark, 390 px), commit**

```bash
git add -A
git commit -m "feat: update banner in the UI; CI signs SHA256SUMS on tags

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
