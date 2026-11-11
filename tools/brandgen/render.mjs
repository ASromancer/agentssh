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
