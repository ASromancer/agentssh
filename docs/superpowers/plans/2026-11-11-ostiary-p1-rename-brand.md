# Ostiary P1: rename and brand. Implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename agentssh to Ostiary everywhere (clean break) and give it a logo, app icon, favicon, tray icon and teal accent.

**Architecture:** The rename is a mechanical case-preserving substitution across tracked files outside `docs/`, followed by a display-name pass. Brand sources (SVG) and rendered PNGs live in a new `internal/brand` package that embeds them. The package also packs them into ICO and ICNS. The tray, UI and later packaging (P3) all read from it. `tools/brandgen` renders the PNGs (Chrome headless, run by hand) and writes ICO/ICNS for packaging.

**Tech Stack:** Go 1.26 stdlib (`embed`, `encoding/binary`, `image/png`); Node and Chrome headless for one-off rendering only.

**Spec:** `docs/superpowers/specs/2026-11-11-ostiary-release-design.md` (§2, §3)

## Global Constraints

- Identifiers are lowercase `ostiary`, env vars are `OSTIARY_*`, and the module is `github.com/ASromancer/ostiary`. User-visible product name is `Ostiary`.
- Clean break: no code reads, migrates or deletes anything named agentssh.
- `docs/` is history. Do not edit files under `docs/` except where a task says so.
- No new Go dependencies. Do not add Node packages; `.mjs` scripts use only Node built-ins plus a `google-chrome` binary.
- UI constraints are unchanged:
  - CSP `default-src 'self'`.
  - No `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `document.write`.
  - No inline script or style.
  - Agent text only via `textContent`.
- Commit as ASromancer only (already configured). End commit messages with a blank line plus `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Go toolchain: `export PATH=$HOME/.local/sdk/go/bin:$PATH`.
- The developer machine runs an agentssh Claude Code hook. It blocks shell commands that mention the old service name, stop or restart the daemon, or touch the old config paths. If a command is blocked, rephrase it (for example, split it or use a file edit). Never try to disable the hook. Never touch `~/.config/agentssh`, `~/.local/state/agentssh` or the running daemon.

---

### Task 1: Mechanical rename agentssh → ostiary

**Files:**
- Modify: every tracked file outside `docs/` that contains `agentssh`, `AGENTSSH` or `Agentssh` (about 45 files: `go.mod`, `main.go`, `internal/**`, `plugin/**`, `.claude-plugin/marketplace.json`, `.github/workflows/ci.yml`, `scripts/e2e.py`, `README.md`, `.gitignore`)
- Rename: `plugin/skills/agentssh/` → `plugin/skills/ostiary/`
- Modify: `internal/hook/hook.go` (humanOnly list)
- Modify: `README.md` (add a "Moving from agentssh" section)

**Interfaces:**
- Produces: module path `github.com/ASromancer/ostiary`, binary name `ostiary`, env vars `OSTIARY_SOCKET`, `OSTIARY_OS_AUTH`, `OSTIARY_NO_TRAY`, `OSTIARY_E2E_HUMANOK`, `OSTIARY_E2E_NOTES`, `OSTIARY_TITLE`, `OSTIARY_BODY` and `OSTIARY_LINK`. Paths become `~/.config/ostiary`, `ostiary.sock`, `ostiary.service`, `dev.ostiary`, `dev.ostiary.confirm` and the repo config file `.ostiary.toml`. Later tasks and plans use these names.

- [ ] **Step 1: Rename the skill directory and substitute**

```bash
cd /home/hiepnt/ai_agent_ssh
git mv plugin/skills/agentssh plugin/skills/ostiary
git ls-files -z | grep -zv '^docs/' | xargs -0 grep -lZ -i 'agentssh' \
  | xargs -0 sed -i -e 's/AGENTSSH/OSTIARY/g' -e 's/Agentssh/Ostiary/g' -e 's/agentssh/ostiary/g'
```

- [ ] **Step 2: Display-name pass**

Product names shown to a human become `Ostiary`. Identifiers, commands, paths and env vars stay lowercase. Find candidates:

```bash
grep -rn 'ostiary' internal/approval internal/tray internal/humanok internal/ui/static/index.html internal/cli/human.go plugin/.claude-plugin .claude-plugin README.md | grep -v -e 'ostiary [a-z-]*\b' -e '/ostiary' -e 'ostiary\.' -e 'OSTIARY_'
```

Change to `Ostiary` where a person reads the word as a name:
- notification titles (`Notice{Title: ...}`);
- tray tooltip `tray.Title`: `Ostiary`, `Ostiary: %d yêu cầu chờ duyệt`;
- polkit `<message>`/`<description>` text;
- Windows CredUI caption;
- macOS LocalAuthentication reason;
- UI `<title>` and the sidebar brand text;
- README title and prose that names the product.

Keep lowercase in:
- command examples (`ostiary run …`);
- the polkit action id;
- the plugin/MCP server `name` fields, because they are identifiers.

Update `internal/tray/tray_test.go` `TestTitle` expectations to `Ostiary` and `Ostiary: 3 yêu cầu chờ duyệt`.

- [ ] **Step 3: humanOnly additions**

In `internal/hook/hook.go`, add `"open"`, `"upgrade"` and `"uninstall-service"` to the human-only command set. These commands arrive in P3/P4. Listing them now means agents can never run them. Add a test case to the existing hook test table for each one, asserting a deny like the existing `ui` case. Copy the shape of the existing `ui` row.

- [ ] **Step 4: README migration section**

Add this section near the install instructions in `README.md`. Match the README's language (English):

```markdown
## Moving from agentssh

Ostiary is the new name of agentssh and starts from a clean slate; it does not read agentssh's data.

1. Remove the old agent hooks: delete the `agentssh hook …` entries from `~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.gemini/settings.json` and Antigravity's `hooks.json` (and the agentssh Claude Code plugin, if installed).
2. Stop and disable the old service: `systemctl --user disable --now agentssh` (Linux), `launchctl unload -w ~/Library/LaunchAgents/dev.agentssh.plist` (macOS), `schtasks /Delete /TN agentssh /F` (Windows).
3. Install Ostiary, run `ostiary init` (or open the app), then add your hosts and keys again.
4. When everything works, delete `~/.config/agentssh` and `~/.local/state/agentssh` (on Windows `%APPDATA%\agentssh` and `%LOCALAPPDATA%\agentssh`).
```

- [ ] **Step 5: Verify nothing old remains**

```bash
git grep -n -i agentssh -- ':!docs'
```
Expected: only lines inside the "Moving from agentssh" README section.

- [ ] **Step 6: Build and test on all targets**

```bash
export PATH=$HOME/.local/sdk/go/bin:$PATH
gofmt -l . ; go vet ./... && for os in linux darwin windows; do GOOS=$os go vet ./... || exit 1; done
go vet -tags e2efake ./...
go test -race ./...
node --check internal/ui/static/app.js && node internal/ui/testdata/highlight_test.mjs
go build -tags e2efake -o /tmp/ostiary-e2e-bin . && python3 scripts/e2e.py /tmp/ostiary-e2e-bin
```
Expected: gofmt prints nothing, everything passes, and e2e prints `all 70 checks passed`. The e2e script must use temp dirs and `OSTIARY_*` env. Confirm it does not touch real `~/.config/ostiary` (run `ls ~/.config/ostiary` before and after; it should not exist).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor: rename agentssh to Ostiary

Clean break: new module path, binary, env vars (OSTIARY_*), config and
state dirs, socket, service names and polkit action; nothing reads the
old agentssh data. README explains the manual move.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Brand package: sources, rendered PNGs, ICO/ICNS packers

**Files:**
- Create: `internal/brand/mark.svg`, `internal/brand/app-icon.svg`, `internal/brand/README.md`
- Create: `internal/brand/brand.go`, `internal/brand/brand_test.go`
- Create: `internal/brand/png/ostiary-{16,32,48,64,128,256,512,1024}.png` (rendered)
- Create: `tools/brandgen/render.mjs`, `tools/brandgen/main.go`

**Interfaces:**
- Consumes: module path from Task 1.
- Produces, in package `github.com/ASromancer/ostiary/internal/brand`:
  - `func PNG(size int) []byte` returns the embedded PNG for one of the sizes 16, 32, 48, 64, 128, 256, 512, 1024, or nil for any other size.
  - `func ICO(sizes ...int) []byte` returns an ICO holding PNG payloads for the given sizes, in order.
  - `func ICNS() []byte` returns an ICNS holding icp4(16), icp5(32), icp6(64), ic07(128), ic08(256), ic09(512) and ic10(1024).
  - `var MarkSVG []byte` and `var AppIconSVG []byte` hold the embedded sources.
- `tools/brandgen`: `go run ./tools/brandgen -out DIR` writes `DIR/ostiary.ico` (sizes 16, 32, 48, 64, 128, 256) and `DIR/ostiary.icns`.

- [ ] **Step 1: Write the SVG sources**

`internal/brand/mark.svg` is the doorway with a keyhole knocked out (evenodd), in `currentColor`, viewBox 64:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="currentColor">
  <path fill-rule="evenodd" d="M12 60V28a20 20 0 0 1 40 0v32zM28.6 38.1a7 7 0 1 1 6.8 0L37.5 49h-11z"/>
</svg>
```

`internal/brand/app-icon.svg` is the rounded tile with the teal gradient and the mark in near-white. The keyhole shows the gradient through it:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0F766E"/>
      <stop offset="1" stop-color="#134E4A"/>
    </linearGradient>
  </defs>
  <rect width="1024" height="1024" rx="224" fill="url(#g)"/>
  <path fill="#F0FDFA" fill-rule="evenodd" transform="translate(192 176) scale(10)"
        d="M12 60V28a20 20 0 0 1 40 0v32zM28.6 38.1a7 7 0 1 1 6.8 0L37.5 49h-11z"/>
</svg>
```

`internal/brand/README.md` holds the brand rules:

```markdown
# Ostiary brand

- Name: **Ostiary** (doorkeeper). Command: `ostiary`.
- Tagline: "The doorkeeper between AI agents and your servers." / "Người gác cửa giữa AI agent và máy chủ của bạn."
- Mark: an arched doorway with a keyhole (`mark.svg`, uses `currentColor`). App icon: `app-icon.svg`.
- Colours: teal `#0F766E` (light UI accent, AA with white text), `#2DD4BF` (dark UI accent), tile gradient `#0F766E → #134E4A`, mark `#F0FDFA`. Teal is reserved for the brand/accent; risk levels keep grey/amber/red/purple.
- Wordmark: system UI font, weight 600, letter-spacing -0.01em, next to the mark; clear space around the mark ≥ 25% of its height; minimum size 16 px.
- PNGs in `png/` are rendered from `app-icon.svg` by `tools/brandgen/render.mjs`; ICO/ICNS are packed from them by `go run ./tools/brandgen -out DIR`.
```

- [ ] **Step 2: Render the PNGs**

`tools/brandgen/render.mjs` renders `app-icon.svg` to every size using Chrome headless over the DevTools protocol (Node built-ins only):

```js
// Renders internal/brand/app-icon.svg to internal/brand/png/ostiary-<n>.png.
// Usage: node tools/brandgen/render.mjs   (needs google-chrome on PATH)
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = new URL("../../internal/brand/", import.meta.url).pathname;
const svg = readFileSync(join(root, "app-icon.svg"), "utf8");
const sizes = [16, 32, 48, 64, 128, 256, 512, 1024];
const port = 9300 + Math.floor(Math.random() * 500);
const prof = mkdtempSync(join(tmpdir(), "brandgen-"));
const ch = spawn("google-chrome", ["--headless=new", "--no-sandbox", "--disable-gpu",
  `--remote-debugging-port=${port}`, `--user-data-dir=${prof}`, "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let tgt;
for (let i = 0; i < 50 && !tgt; i++) {
  try { tgt = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find((t) => t.type === "page"); } catch {}
  if (!tgt) await sleep(200);
}
const ws = new WebSocket(tgt.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pend = new Map();
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); } };
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
await send("Page.enable");
mkdirSync(join(root, "png"), { recursive: true });
for (const n of sizes) {
  await send("Emulation.setDeviceMetricsOverride", { width: n, height: n, deviceScaleFactor: 1, mobile: false });
  await send("Emulation.setDefaultBackgroundColorOverride", { color: { r: 0, g: 0, b: 0, a: 0 } });
  const html = `<html><body style="margin:0;background:transparent">${svg.replace("<svg ", `<svg width="${n}" height="${n}" `)}</body></html>`;
  await send("Page.navigate", { url: "data:text/html;base64," + Buffer.from(html).toString("base64") });
  await sleep(300);
  const r = await send("Page.captureScreenshot", { format: "png", clip: { x: 0, y: 0, width: n, height: n, scale: 1 } });
  writeFileSync(join(root, "png", `ostiary-${n}.png`), Buffer.from(r.result.data, "base64"));
  console.log("wrote", n);
}
ch.kill();
process.exit(0);
```

Run: `node tools/brandgen/render.mjs`
Expected: 8 files in `internal/brand/png/`. Check that each is an RGBA PNG of the right size with transparent corners. Open `ostiary-256.png` with the Read tool and confirm visually that the tile, doorway and keyhole look right.

- [ ] **Step 3: Write the failing test for the packers**

`internal/brand/brand_test.go`:

```go
package brand

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
)

func TestPNGSizes(t *testing.T) {
	for _, n := range []int{16, 32, 48, 64, 128, 256, 512, 1024} {
		img, err := png.Decode(bytes.NewReader(PNG(n)))
		if err != nil || img.Bounds().Dx() != n || img.Bounds().Dy() != n {
			t.Fatalf("size %d: %v", n, err)
		}
	}
	if PNG(20) != nil {
		t.Fatal("unknown size must return nil")
	}
}

func TestICO(t *testing.T) {
	ico := ICO(16, 256)
	le := binary.LittleEndian
	if le.Uint16(ico[0:]) != 0 || le.Uint16(ico[2:]) != 1 || le.Uint16(ico[4:]) != 2 {
		t.Fatalf("header % x", ico[:6])
	}
	for i, n := range []int{16, 256} {
		e := ico[6+16*i:]
		w := int(e[0])
		if w == 0 {
			w = 256
		}
		size, off := le.Uint32(e[8:]), le.Uint32(e[12:])
		if w != n || le.Uint16(e[6:]) != 32 || !bytes.Equal(ico[off:off+size], PNG(n)) {
			t.Fatalf("entry %d wrong", i)
		}
	}
}

func TestICNS(t *testing.T) {
	b := ICNS()
	be := binary.BigEndian
	if string(b[:4]) != "icns" || int(be.Uint32(b[4:])) != len(b) {
		t.Fatalf("header %q %d/%d", b[:4], be.Uint32(b[4:]), len(b))
	}
	want := map[string]int{"icp4": 16, "icp5": 32, "icp6": 64, "ic07": 128, "ic08": 256, "ic09": 512, "ic10": 1024}
	for p := 8; p < len(b); {
		typ, n := string(b[p:p+4]), int(be.Uint32(b[p+4:]))
		size, ok := want[typ]
		if !ok || !bytes.Equal(b[p+8:p+n], PNG(size)) {
			t.Fatalf("entry %s wrong", typ)
		}
		delete(want, typ)
		p += n
	}
	if len(want) != 0 {
		t.Fatalf("missing %v", want)
	}
}
```

Run: `go test ./internal/brand/`
Expected: FAIL to compile (`PNG`, `ICO`, `ICNS` undefined).

- [ ] **Step 4: Implement `internal/brand/brand.go`**

```go
// Package brand holds the Ostiary logo sources, the rendered PNGs and the
// ICO/ICNS packers used by the tray, the web UI and the installers.
package brand

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"
)

//go:embed png/*.png
var pngs embed.FS

//go:embed mark.svg
var MarkSVG []byte

//go:embed app-icon.svg
var AppIconSVG []byte

// PNG returns the app icon rendered at size×size, or nil if that size is not shipped.
func PNG(size int) []byte {
	b, err := pngs.ReadFile(fmt.Sprintf("png/ostiary-%d.png", size))
	if err != nil {
		return nil
	}
	return b
}

// ICO packs the given sizes as PNG payloads (Windows Vista and later).
func ICO(sizes ...int) []byte {
	var hdr, data bytes.Buffer
	le := func(v any) { binary.Write(&hdr, binary.LittleEndian, v) }
	le(uint16(0))
	le(uint16(1))
	le(uint16(len(sizes)))
	off := 6 + 16*len(sizes)
	for _, n := range sizes {
		p := PNG(n)
		dim := byte(n)
		if n >= 256 {
			dim = 0
		}
		hdr.Write([]byte{dim, dim, 0, 0})
		le(uint16(1))
		le(uint16(32))
		le(uint32(len(p)))
		le(uint32(off + data.Len()))
		data.Write(p)
	}
	return append(hdr.Bytes(), data.Bytes()...)
}

// ICNS packs the macOS icon family with PNG payloads.
func ICNS() []byte {
	var body bytes.Buffer
	for _, e := range []struct {
		typ  string
		size int
	}{{"icp4", 16}, {"icp5", 32}, {"icp6", 64}, {"ic07", 128}, {"ic08", 256}, {"ic09", 512}, {"ic10", 1024}} {
		p := PNG(e.size)
		body.WriteString(e.typ)
		binary.Write(&body, binary.BigEndian, uint32(8+len(p)))
		body.Write(p)
	}
	var out bytes.Buffer
	out.WriteString("icns")
	binary.Write(&out, binary.BigEndian, uint32(8+body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/brand/`
Expected: PASS.

- [ ] **Step 6: `tools/brandgen/main.go`**

```go
// Command brandgen writes ostiary.ico and ostiary.icns for the installers.
// Usage: go run ./tools/brandgen -out DIR
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/ASromancer/ostiary/internal/brand"
)

func main() {
	out := flag.String("out", ".", "output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"ostiary.ico":  brand.ICO(16, 32, 48, 64, 128, 256),
		"ostiary.icns": brand.ICNS(),
	} {
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
```

Run: `go run ./tools/brandgen -out /tmp/brand-out && file /tmp/brand-out/*`
Expected: `ostiary.ico: MS Windows icon resource - 6 icons…` and `ostiary.icns: Mac OS X icon…`.

- [ ] **Step 7: Commit**

```bash
git add internal/brand tools/brandgen
git commit -m "feat(brand): Ostiary mark, app icon, rendered PNGs and ICO/ICNS packers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Use the brand in the tray and the web UI

**Files:**
- Modify: `internal/tray/icon.go`, `internal/tray/tray_test.go`
- Modify: `internal/ui/server.go` (routes `/favicon.png`, `/brand/mark.svg`), `internal/ui/server_test.go`
- Modify: `internal/ui/static/index.html`, `internal/ui/static/app.css`, `internal/ui/static/static_test.go` if it pins brand markup

**Interfaces:**
- Consumes: `brand.PNG(int) []byte`, `brand.ICO(...int) []byte`, `brand.MarkSVG` from Task 2.
- Produces: `GET /favicon.png` (image/png, the 64px icon) and `GET /brand/mark.svg` (`image/svg+xml`). Both are static, behind the same guard and security headers as other static files. Both are fetched with no cookie, before login, exactly like `/app.css`. Follow how the files map handles static assets.

- [ ] **Step 1: Tray uses the brand icon (test first)**

Change `TestIcon` in `internal/tray/tray_test.go` to expect `Icon("linux")` to equal `brand.PNG(32)` (32×32). On Windows, `Icon("windows")` must equal `brand.ICO(16, 32)`, with an ICO header of count 2. Run `go test ./internal/tray/` and confirm it fails. Then replace the drawn icon in `internal/tray/icon.go`:

```go
// Icon returns the tray icon: the brand PNG, or an ICO on Windows.
func Icon(goos string) []byte {
	if goos == "windows" {
		return brand.ICO(16, 32)
	}
	return brand.PNG(32)
}
```

Delete `icoWrap` and the drawing code, and drop the now-unused imports. Run `go test ./internal/tray/`, which should pass.

- [ ] **Step 2: UI serves favicon and mark (test first)**

In `internal/ui/server_test.go`, add a test in the style of `TestStatic`:
- `GET /favicon.png` returns 200, `Content-Type: image/png`, and a body equal to `brand.PNG(64)`;
- `GET /brand/mark.svg` returns 200, `Content-Type: image/svg+xml`, and a body equal to `brand.MarkSVG`;
- both carry the CSP header.

Run it and confirm it fails. Then add both to the explicit files mechanism in `internal/ui/server.go`. The map today points to files in the static FS. Add these two entries backed by the brand bytes, either by extending the entry struct with an optional `body []byte` or with a small explicit handler that sets the same headers. Run the test again, which should pass.

- [ ] **Step 3: Brand in the page**

`index.html`:
- add `<link rel="icon" href="/favicon.png">` in `<head>`;
- set `<title>Ostiary</title>`;
- replace the sidebar brand `<span class="logo"><i data-icon="terminal"></i></span><span>…</span>` with `<span class="logo"><img src="/brand/mark.svg" alt="" width="20" height="20"></span><span class="wordmark">Ostiary</span>`.

Apply the same to the compact (top/bottom nav) brand if `index.html` has one.

`app.css`:
- `--accent: light-dark(#0f766e, #2dd4bf);`
- `--accent-fg: light-dark(#fff, #042f2e);`
- `.logo img` shows the mark in white on the accent tile. The SVG uses `currentColor`, which does not apply through `<img>`, so put a CSS filter on the img: `.logo img { filter: brightness(0) invert(1); }` in light mode, and `filter: brightness(0)` in dark mode (dark text on teal), using `@media (prefers-color-scheme: dark)` and the theme toggle class the stylesheet already uses for dark mode.
- `.wordmark { font-weight: 600; letter-spacing: -0.01em; }`

Grep `app.css` for any other hard-coded old blue (`#2563eb`, `#5b94ff`, `37, 99, 235`) and route them through `var(--accent)`.

- [ ] **Step 4: Verify visually and run all checks**

Run the full check list from Task 1 Step 6, which must all pass. Then take screenshots of approvals and hosts in light and dark at 1440×900 and 390×844. Use a temporary demo test that starts the UI with the fake backend (see `internal/ui/fake_test.go` and `Start(Options{Backend: &fakeBackend{}})`) and `/tmp/shot.mjs`, or an equivalent CDP script. Delete the demo test afterwards and never commit it. Look at each screenshot with the Read tool. Check that:
- the mark is visible on its tile;
- the teal accent is legible;
- the focus ring is visible;
- primary buttons have readable text.

Save the screenshots to `/tmp/shots/ostiary-*.png`.

- [ ] **Step 5: Commit**

```bash
git add internal/tray internal/ui
git commit -m "feat(ui,tray): Ostiary logo, favicon, tray icon and teal accent

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
