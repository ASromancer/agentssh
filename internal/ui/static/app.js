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
