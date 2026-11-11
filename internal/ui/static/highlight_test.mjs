// Run: node internal/ui/static/highlight_test.mjs  (not part of go test)
import { readFileSync } from "node:fs";
import assert from "node:assert";
const src = readFileSync(new URL("./app.js", import.meta.url), "utf8");
const byteToJs = new Function(src.match(/function byteToJs[\s\S]*?\n}\n/)[0] + "; return byteToJs;")();
// "é" 2 bytes, "€" 3 bytes, "😀" 4 bytes (2 UTF-16 units), then "rm"
const cmd = "é€😀rm";
const m = byteToJs(cmd);
assert.strictEqual(m[2], 1);   // after é
assert.strictEqual(m[5], 2);   // after €
assert.strictEqual(m[9], 4);   // after 😀 (2 units)
assert.strictEqual(cmd.slice(m[9], m[11]), "rm");
assert.strictEqual(m[11], cmd.length);
console.log("highlight ok");
