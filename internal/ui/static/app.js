"use strict";
// agentssh UI (vanilla JS, no build). All text from the daemon (commands,
// notes, host names, audit fields) is agent-controlled: it enters the page
// only through textContent / text nodes, never as HTML.

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
};
const PAGE = 50;
const VIEWS = { approvals: "Duyệt", hosts: "Host", keychain: "Kho khóa", knownhosts: "Known hosts", log: "Nhật ký" };
let status = null;
let auditOffset = 0;
let view = "approvals";
let hostData = { Hosts: {}, Trusted: {} };

// ---- icons (createElementNS, stroke style) ----
const ICONS = {
  terminal: ["M4 17l6-6-6-6", "M12 19h8"],
  shield: ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"],
  shieldcheck: ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z", "M9 12l2 2 4-4"],
  server: ["M4 3h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z", "M4 14h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2z", "M6 6.5h.01", "M6 17.5h.01"],
  key: ["M15 7a5 5 0 1 1-4.6 6.9L3 21.3V24h3v-2h2v-2h2l1.4-1.4A5 5 0 0 1 15 7z", "M16.5 8.5h.01"],
  lock: ["M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2z", "M7 11V7a5 5 0 0 1 10 0v4"],
  unlock: ["M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2z", "M7 11V7a5 5 0 0 1 9.9-1"],
  list: ["M8 6h13", "M8 12h13", "M8 18h13", "M3 6h.01", "M3 12h.01", "M3 18h.01"],
  fingerprint: ["M12 11v3a8 8 0 0 1-1 4", "M8 14a8 8 0 0 0 1 5", "M16 13a12 12 0 0 1-2 7", "M5 10a7 7 0 0 1 13-3.5", "M19 11v1a13 13 0 0 1-1 4", "M9 9.5a3 3 0 0 1 6 1"],
  sun: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z", "M12 2v2", "M12 20v2", "M4.9 4.9l1.4 1.4", "M17.7 17.7l1.4 1.4", "M2 12h2", "M20 12h2", "M6.3 17.7l-1.4 1.4", "M19.1 4.9l-1.4 1.4"],
  moon: ["M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"],
  check: ["M20 6L9 17l-5-5"],
  x: ["M18 6L6 18", "M6 6l12 12"],
  copy: ["M9 9h11a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2z", "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"],
  plus: ["M12 5v14", "M5 12h14"],
  refresh: ["M21 12a9 9 0 1 1-3-6.7L21 8", "M21 3v5h-5"],
  trash: ["M3 6h18", "M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2", "M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"],
  more: ["M5 12h.01", "M12 12h.01", "M19 12h.01"],
  pencil: ["M12 20h9", "M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"],
  search: ["M11 3a8 8 0 1 0 0 16 8 8 0 0 0 0-16z", "M21 21l-4.3-4.3"],
  alert: ["M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z", "M12 9v4", "M12 17h.01"],
  info: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M12 16v-4", "M12 8h.01"],
  ban: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M4.9 4.9l14.2 14.2"],
  chevl: ["M15 18l-6-6 6-6"],
  chevr: ["M9 18l6-6-6-6"],
  upload: ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "M17 8l-5-5-5 5", "M12 3v12"],
};
const SVGNS = "http://www.w3.org/2000/svg";
function icon(name, size) {
  const s = document.createElementNS(SVGNS, "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("fill", "none");
  s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "2");
  s.setAttribute("stroke-linecap", "round");
  s.setAttribute("stroke-linejoin", "round");
  s.setAttribute("aria-hidden", "true");
  s.setAttribute("class", "ic");
  if (size) { s.setAttribute("width", size); s.setAttribute("height", size); }
  (ICONS[name] || []).forEach((d) => {
    const p = document.createElementNS(SVGNS, "path");
    p.setAttribute("d", d);
    s.appendChild(p);
  });
  return s;
}
document.querySelectorAll("i[data-icon]").forEach((i) => i.replaceWith(icon(i.dataset.icon)));

// ---- API ----
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

// ---- toasts ----
function toast(msg, kind) {
  const t = el("div", "toast " + (kind === "error" ? "bad" : kind === "ok" ? "ok" : ""));
  t.appendChild(icon(kind === "error" ? "alert" : kind === "ok" ? "check" : "info"));
  t.appendChild(el("div", "msg", msg));
  const x = el("button", "copybtn");
  x.type = "button";
  x.setAttribute("aria-label", "Đóng thông báo");
  x.appendChild(icon("x"));
  const gone = () => { t.classList.add("out"); setTimeout(() => t.remove(), 160); };
  x.addEventListener("click", gone);
  t.appendChild(x);
  $("toasts").appendChild(t);
  if (kind !== "error") setTimeout(gone, 5000); // errors stay until closed
}
const ok = (m) => toast(m, "ok");
const fail = (e) => toast(e && e.message ? e.message : String(e), "error");

async function busy(button, fn) {
  button.disabled = true;
  button.classList.add("loading");
  try { await fn(); } catch (e) { fail(e); } finally { button.disabled = false; button.classList.remove("loading"); }
}

function copyText(text, btn) {
  const done = () => {
    ok("Đã copy");
    if (btn) {
      clearTimeout(btn._t);
      if (!btn._old) btn._old = btn.firstChild;
      btn.replaceChildren(icon("check"));
      btn._t = setTimeout(() => btn.replaceChildren(btn._old), 1400);
    }
  };
  if (!navigator.clipboard) { fail(new Error("Trình duyệt không cho copy")); return; }
  navigator.clipboard.writeText(text).then(done, () => fail(new Error("Không copy được")));
}
function copyBtn(text, label) {
  const b = el("button", "copybtn");
  b.type = "button";
  b.setAttribute("aria-label", label || "Copy");
  b.title = label || "Copy";
  b.appendChild(icon("copy"));
  b.addEventListener("click", (e) => { e.stopPropagation(); copyText(typeof text === "function" ? text() : text, b); });
  return b;
}

// ---- layers: modal and drawer (focus trap, Esc, restore focus) ----
const layers = [];
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
function openLayer(kind, title) {
  const prev = document.activeElement;
  const back = el("div", "backdrop bd-" + kind);
  const box = el("div", kind);
  const hid = "layer-title-" + layers.length + "-" + Date.now();
  box.setAttribute("role", "dialog");
  box.setAttribute("aria-modal", "true");
  box.setAttribute("aria-labelledby", hid);
  box.tabIndex = -1;
  const head = el("div", "layer-head");
  const h = el("h2", null, title);
  h.id = hid;
  const x = el("button", "iconbtn");
  x.type = "button";
  x.setAttribute("aria-label", "Đóng");
  x.appendChild(icon("x"));
  head.append(h, x);
  const body = el("div", "layer-body");
  const foot = el("div", "layer-foot");
  box.append(head, body, foot);
  back.appendChild(box);
  const layer = { box, body, foot, onClose: null, closed: false };
  layer.close = () => {
    if (layer.closed) return;
    layer.closed = true;
    layers.splice(layers.indexOf(layer), 1);
    back.classList.add("out");
    setTimeout(() => back.remove(), 150);
    if (prev && prev.focus && document.contains(prev)) prev.focus();
    if (layer.onClose) layer.onClose();
  };
  layer.title = (t) => { h.textContent = t; };
  x.addEventListener("click", layer.close);
  // layer.dirty (optional): unsaved input, so backdrop click and Esc must not discard it
  back.addEventListener("mousedown", (e) => { if (e.target === back && !(layer.dirty && layer.dirty())) layer.close(); });
  document.body.appendChild(back);
  layers.push(layer);
  layer.focusFirst = () => {
    const f = box.querySelector("[data-autofocus]") || body.querySelector(FOCUSABLE) || foot.querySelector(FOCUSABLE) || box;
    f.focus();
  };
  return layer;
}
document.addEventListener("keydown", (e) => {
  const top = layers[layers.length - 1];
  if (!top) return;
  if (e.key === "Escape") { e.preventDefault(); if (!(top.dirty && top.dirty())) top.close(); return; }
  if (e.key !== "Tab") return;
  const items = Array.from(top.box.querySelectorAll(FOCUSABLE)).filter((n) => n.offsetParent !== null);
  if (!items.length) { e.preventDefault(); return; }
  const first = items[0], last = items[items.length - 1];
  if (e.shiftKey && (document.activeElement === first || document.activeElement === top.box)) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  else if (!top.box.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
});

function button(label, cls, iconName) {
  const b = el("button", "btn" + (cls ? " " + cls : ""));
  b.type = "button";
  if (iconName) b.appendChild(icon(iconName));
  b.appendChild(document.createTextNode(label));
  return b;
}

function field(label, input, hint, errBox) {
  const f = el("div", "field");
  const id = input.id || (input.id = "f" + Math.random().toString(36).slice(2, 8));
  const l = el("label", null, label);
  l.htmlFor = id;
  f.append(l, input);
  if (hint) f.appendChild(el("div", "hint", hint));
  const err = errBox || el("div", "err");
  err.id = id + "-err";
  err.setAttribute("role", "alert");
  f.appendChild(err);
  f._err = err;
  f._input = input;
  return f;
}
function setErr(f, msg) {
  f._err.textContent = msg || "";
  if (msg) f._input.setAttribute("aria-invalid", "true"); else f._input.removeAttribute("aria-invalid");
}

// askForm: promise of {name: value} or null. fields: {name,label,type,placeholder,hint,required,mono,file,autocomplete}
function askForm(o) {
  return new Promise((resolve) => {
    const layer = openLayer("modal", o.title);
    let result = null;
    const form = el("form");
    form.noValidate = true;
    form.id = "form-" + Date.now();
    if (o.desc) form.appendChild(el("p", null, o.desc));
    if (o.info) form.appendChild(el("div", "infobox", o.info));
    const built = (o.fields || []).map((d) => {
      const inp = el("input", "input" + (d.mono ? " mono" : ""));
      inp.type = d.type || "text";
      inp.name = d.name;
      if (d.placeholder) inp.placeholder = d.placeholder;
      inp.autocomplete = d.autocomplete || "off";
      inp.spellcheck = false;
      const f = field(d.label, inp, d.hint);
      form.appendChild(f);
      return { d, inp, f };
    });
    if (built[0]) built[0].inp.setAttribute("data-autofocus", "");
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const vals = {};
      let bad = null;
      built.forEach(({ d, inp, f }) => {
        const v = d.type === "file" ? inp.files[0] : inp.value;
        const empty = d.type === "file" ? !v : !String(v).trim();
        if (d.required && empty) { setErr(f, d.errmsg || "Trường này là bắt buộc"); bad = bad || inp; } else setErr(f, "");
        vals[d.name] = v;
      });
      if (bad) { bad.focus(); return; }
      result = vals;
      layer.close();
    });
    layer.body.appendChild(form);
    const cancel = button(o.cancel || "Hủy", "ghost");
    cancel.addEventListener("click", layer.close);
    const submit = button(o.ok || "Xác nhận", o.danger ? "danger solid" : "primary");
    submit.type = "submit";
    submit.setAttribute("form", form.id);
    layer.foot.append(cancel, submit);
    layer.onClose = () => resolve(result);
    layer.focusFirst();
    if (!built.length) submit.focus();
  });
}
const confirmBox = (title, desc, o) => askForm(Object.assign({ title, desc }, o)).then(Boolean);

function waitLayer(title, text) {
  const l = openLayer("modal", title);
  const b = el("div", "waitbody");
  b.append(el("span", "spin lg"), el("p", null, text));
  b.setAttribute("role", "status");
  l.body.appendChild(b);
  l.focusFirst();
  return l;
}

// ---- theme ----
function applyTheme(t) {
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  const dark = t ? t === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  $("theme").replaceChildren(icon(dark ? "sun" : "moon"));
}
(() => {
  let saved = null;
  try { saved = localStorage.getItem("agentssh-theme"); } catch (e) { /* storage blocked */ }
  applyTheme(saved === "light" || saved === "dark" ? saved : null);
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => applyTheme(document.documentElement.dataset.theme || null));
  $("theme").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme ? document.documentElement.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    const next = dark ? "light" : "dark";
    try { localStorage.setItem("agentssh-theme", next); } catch (e) { /* ignore */ }
    applyTheme(next);
  });
})();

// ---- navigation ----
document.querySelectorAll("[data-nav]").forEach((b) => b.addEventListener("click", () => showView(b.dataset.nav)));
function showView(name) {
  view = name;
  document.querySelectorAll("[data-nav]").forEach((b) => {
    if (b.dataset.nav === name) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  });
  document.querySelectorAll("[data-view]").forEach((s) => s.classList.toggle("active", s.dataset.view === name));
  $("title").textContent = VIEWS[name];
  if (location.hash !== "#" + name && !location.hash.startsWith("#req=")) history.replaceState(null, "", "#" + name);
  const run = (p) => p.catch(fail);
  if (name === "hosts") run(loadHosts());
  if (name === "keychain") run(loadKeychain());
  if (name === "knownhosts") run(loadKnownHosts());
  if (name === "log") { run(loadChecks()); run(loadAudit()); }
}

// ---- status ----
async function loadStatus() {
  const r = await call("GET", "/api/status");
  status = r.status;
  $("version").textContent = "v" + r.version;
  const os = status.Auth === "os";
  const am = $("authmode");
  am.replaceChildren(icon(os ? "shieldcheck" : "key"), document.createTextNode(os ? "Xác thực hệ điều hành" : "Mã duyệt"));
  am.title = os ? "" : (status.AuthNote || "");
  const vs = $("vaultstate");
  vs.classList.toggle("ok", !status.Locked);
  vs.classList.toggle("warn", !!status.Locked);
  vs.replaceChildren(icon(status.Locked ? "lock" : "unlock"), document.createTextNode(status.Locked ? "Vault đang khóa" : "Vault đang mở"));
  const n = status.Pending ? String(status.Pending) : "";
  $("pendingcount").textContent = n;
  document.title = (n ? "(" + n + ") " : "") + "agentssh";
  $("configwarn").classList.toggle("hidden", !status.UserOnly);
}
async function toggleVault() {
  if (!status) return;
  if (!status.Locked) { await call("POST", "/api/lock"); ok("Đã khóa vault"); return refresh(); }
  let pass = "";
  if (status.Passphrase) {
    const v = await askForm({ title: "Mở khóa vault", desc: "Nhập passphrase của vault.", ok: "Mở khóa", fields: [{ name: "pass", label: "Passphrase", type: "password", required: true }] });
    if (!v) return;
    pass = v.pass;
  } else {
    toast("Hãy xác nhận trong hộp thoại của hệ điều hành…");
  }
  await call("POST", "/api/unlock", { pass });
  ok("Đã mở khóa vault");
  await refresh();
}
$("vaultstate").addEventListener("click", (e) => busy(e.currentTarget, toggleVault));

// ---- approvals ----
// Reason.start/end are UTF-8 byte offsets; JS strings index UTF-16 units.
function byteToJs(cmd) {
  const map = [0]; // map[byteOffset] = JS index (continuation bytes map to the same index)
  let js = 0;
  for (const ch of cmd) {
    const cp = ch.codePointAt(0);
    const n = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    for (let k = 1; k <= n; k++) map.push(k === n ? js + ch.length : js);
    js += ch.length;
  }
  return map;
}

function highlighted(cmd, reasons) {
  const box = el("pre", "cmd");
  const marks = new Array(cmd.length).fill(false);
  const map = byteToJs(cmd);
  const at = (b) => map[Math.min(Math.max(0, b), map.length - 1)];
  (reasons || []).forEach((r) => {
    if (r.level === "destructive" || r.level === "forbidden") {
      for (let i = at(r.start); i < at(r.end) && i < cmd.length; i++) marks[i] = true;
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

const LEVEL_LABEL = { read: "Đọc", mutate: "Thay đổi", destructive: "Phá hủy", forbidden: "Cấm" };
const LEVEL_ICON = { read: "info", mutate: "alert", destructive: "alert", forbidden: "ban" };
function levelPill(level) {
  const p = el("span", "pill " + (LEVEL_LABEL[level] ? level : "neutral"));
  p.textContent = LEVEL_LABEL[level] || level || "";
  return p;
}

function relTime(iso) {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (!(s >= 0)) return "vừa xong";
  if (s < 5) return "vừa xong";
  if (s < 60) return s + " giây trước";
  if (s < 3600) return Math.floor(s / 60) + " phút trước";
  if (s < 86400) return Math.floor(s / 3600) + " giờ trước";
  return new Date(iso).toLocaleString();
}
const hasTime = (iso) => iso && new Date(iso).getFullYear() > 2000;

function metaChip(k, v) {
  if (!v) return null;
  const s = el("span", null, k);
  s.appendChild(el("b", null, v));
  return s;
}

const authCode = () => !!status && status.Auth !== "os";
function buildCard(r) {
  const c = el("article", "card req " + (r.level || ""));
  c.dataset.id = r.id;
  c.id = "req-" + r.id;
  const code = authCode();
  const os = !code;
  c._code = code;
  if (hasTime(r.expires)) {
    const cd = el("div", "countdown");
    cd.setAttribute("role", "progressbar");
    cd.setAttribute("aria-label", "Thời gian còn lại");
    const bar = el("div", "bar");
    cd.appendChild(bar);
    c.appendChild(cd);
    c._bar = bar;
    c._cd = cd;
  }
  const body = el("div", "req-body");
  c.appendChild(body);

  const head = el("div", "req-head");
  const when = el("span", "when");
  head.append(levelPill(r.level), el("span", "id", "#" + r.id), el("span", "host", r.host), when);
  body.appendChild(head);
  c._when = when;
  c._r = r;

  const cmdbox = el("div", "cmdbox");
  cmdbox.appendChild(r.kind === "run" || r.kind === "job" ? highlighted(r.cmd, r.reasons) : el("pre", "cmd", r.cmd));
  cmdbox.appendChild(copyBtn(r.cmd, "Copy lệnh"));
  body.appendChild(cmdbox);

  const why = (r.reasons || []).filter((x) => x.level !== "read");
  if (why.length) {
    const ul = el("ul", "reasons");
    why.forEach((x) => {
      const li = el("li", x.level);
      li.append(icon(LEVEL_ICON[x.level] || "info"), el("span", null, x.text));
      ul.appendChild(li);
    });
    body.appendChild(ul);
  }
  const metas = el("div", "metas");
  [["Agent", r.agent], ["User", r.user], ["cwd", r.cwd], ["Repo", r.repo], ["Loại", r.kind]].forEach(([k, v]) => { const m = metaChip(k, v); if (m) metas.appendChild(m); });
  body.appendChild(metas);

  if (r.code) {
    const w = el("div", "codewarn", "Không gửi được thông báo; mã duyệt: ");
    w.appendChild(el("b", null, r.code));
    body.appendChild(w);
  }

  const wait = el("div", "waiting hidden");
  wait.setAttribute("role", "status");
  wait.append(el("span", "spin"), el("span", null, "Đang chờ xác thực trên hệ điều hành…"));
  body.appendChild(wait);

  const actions = el("div", "actions");
  let codeIn = null;
  if (code) {
    codeIn = el("input", "input codein");
    codeIn.placeholder = "Mã duyệt";
    codeIn.autocomplete = "off";
    codeIn.spellcheck = false;
    codeIn.setAttribute("aria-label", "Mã duyệt cho yêu cầu #" + r.id);
    actions.appendChild(codeIn);
  }
  const noteRow = el("div", "noterow hidden");
  const note = el("input", "input");
  note.placeholder = "Lời nhắn cho agent";
  note.setAttribute("aria-label", "Lời nhắn khi từ chối");
  const buttons = [];
  const decide = (b, choice) => async () => {
    if (codeIn && (choice === "y" || choice === "s") && !codeIn.value.trim()) {
      codeIn.setAttribute("aria-invalid", "true");
      codeIn.focus();
      toast("Nhập mã duyệt từ thông báo trước khi duyệt", "error");
      return;
    }
    buttons.forEach((x) => { x.disabled = true; });
    const osWait = os && choice !== "n" && choice !== "m";
    if (osWait) wait.classList.remove("hidden");
    b.classList.add("loading");
    try {
      await call("POST", "/api/decide", { id: r.id, choice, note: choice === "m" ? note.value : "", code: codeIn ? codeIn.value : "" });
      ok("#" + r.id + ": " + ({ y: "đã duyệt", s: "đã duyệt 30 phút", n: "đã từ chối", m: "đã từ chối kèm lời nhắn" })[choice]);
      refresh();
    } catch (e) {
      fail(e);
      buttons.forEach((x) => { x.disabled = false; });
    } finally {
      wait.classList.add("hidden");
      b.classList.remove("loading");
    }
  };
  const mk = (label, cls, choice, ic) => {
    const b = button(label, cls, ic);
    b.addEventListener("click", () => decide(b, choice)());
    buttons.push(b);
    return b;
  };
  actions.append(mk("Duyệt 1 lần", "primary lg", "y", "check"), mk("Duyệt 30 phút", "lg", "s"));
  actions.appendChild(el("span", "sp"));
  const toggle = button("Từ chối kèm lời nhắn", "ghost");
  toggle.addEventListener("click", () => { noteRow.classList.toggle("hidden"); if (!noteRow.classList.contains("hidden")) note.focus(); });
  actions.append(toggle, mk("Từ chối", "danger lg", "n", "x"));
  body.appendChild(actions);
  noteRow.append(note, mk("Gửi lời từ chối", "danger", "m"));
  body.appendChild(noteRow);
  note.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); noteRow.lastChild.click(); } });
  return c;
}

function tickCards() {
  document.querySelectorAll(".req").forEach((c) => {
    const r = c._r;
    if (!r) return;
    c._when.textContent = relTime(r.time);
    if (!c._bar) return;
    const rem = Math.max(0, Math.round((new Date(r.expires) - Date.now()) / 1000));
    c._when.textContent += rem > 0 ? " · còn " + Math.floor(rem / 60) + ":" + String(rem % 60).padStart(2, "0") : " · đã hết hạn";
    const total = new Date(r.expires) - new Date(r.time);
    const left = new Date(r.expires) - Date.now();
    const frac = total > 0 ? Math.max(0, Math.min(1, left / total)) : 0;
    c._bar.style.width = (frac * 100).toFixed(1) + "%";
    c._bar.classList.toggle("low", frac < 0.4 && frac >= 0.15);
    c._bar.classList.toggle("crit", frac < 0.15);
    const secs = Math.max(0, Math.round(left / 1000));
    c._cd.setAttribute("aria-valuenow", String(Math.round(frac * 100)));
    c._cd.title = left > 0 ? "Còn " + Math.floor(secs / 60) + " phút " + (secs % 60) + " giây" : "Đã hết hạn";
  });
}
setInterval(tickCards, 1000);

async function loadPending() {
  if (!status) await loadStatus(); // cards depend on the auth mode
  const list = await call("GET", "/api/pending");
  const box = $("reqlist");
  $("noreq").classList.toggle("hidden", list.length > 0);
  const have = new Map(Array.from(box.children).map((c) => [Number(c.dataset.id), c]));
  const ids = new Set(list.map((r) => r.id));
  have.forEach((c, id) => { if (!ids.has(id)) c.remove(); });
  const focus = Number((location.hash.match(/req=(\d+)/) || [])[1]);
  list.slice().sort((a, b) => b.id - a.id).forEach((r, i) => { // newest first
    let c = have.get(r.id);
    if (c && c._code !== authCode()) { c.remove(); c = null; } // auth mode changed
    if (!c) c = buildCard(r);
    c.classList.toggle("focus", r.id === focus);
    if (box.children[i] !== c) box.insertBefore(c, box.children[i] || null);
    if (r.id === focus && !c._scrolled) { c._scrolled = true; c.scrollIntoView({ block: "center" }); }
  });
  tickCards();
}

// ---- admin helper: begin -> (info confirm) -> (OS dialog or code) -> commit ----
async function admin(op, name, extra) {
  const b = await call("POST", "/api/admin/begin", { op, name });
  let code = "";
  if (b.Info) {
    const t = op === "trust" ? "Xác nhận host key" : "Xác nhận thao tác";
    if (!(await confirmBox(t, "So sánh với fingerprint bạn mong đợi trước khi tiếp tục.", { info: b.Info, ok: "Tiếp tục" }))) return null;
  }
  let wait = null;
  if (!b.OSAuth) {
    const v = await askForm({
      title: "Nhập mã duyệt", ok: "Xác nhận",
      desc: "Nhập mã trong thông báo vừa hiện trên máy của bạn.",
      info: b.Code ? "Không gửi được thông báo; mã: " + b.Code : null,
      fields: [{ name: "code", label: "Mã duyệt", mono: true, required: true }],
    });
    if (!v) return null;
    code = v.code.trim();
  } else {
    wait = waitLayer("Xác thực hệ điều hành", "Đang chờ xác thực trên hệ điều hành…");
  }
  try {
    const r = await call("POST", "/api/admin/commit", Object.assign({ ticket: b.Ticket, code, op, name }, extra || {}));
    return r.out;
  } finally {
    if (wait) wait.close();
  }
}

// ---- hosts ----
function hashHue(s) { let h = 0; for (const ch of s) h = (h * 31 + ch.codePointAt(0)) >>> 0; return h % 360; }
function initials(name) {
  const parts = name.split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  const a = parts.length > 1 ? parts[0][0] + parts[1][0] : Array.from(name.replace(/[^\p{L}\p{N}]/gu, "")).slice(0, 2).join("");
  return (a || "?").toUpperCase();
}
const addrOf = (h) => (h.user ? h.user + "@" : "") + h.host + ":" + (h.port || 22);
let hostMode = "grid";
try { hostMode = localStorage.getItem("agentssh-hostview") === "list" ? "list" : "grid"; } catch (e) { /* ignore */ }
document.querySelectorAll('input[name="hostview"]').forEach((r) => {
  r.checked = r.value === hostMode;
  r.addEventListener("change", () => {
    hostMode = r.value;
    try { localStorage.setItem("agentssh-hostview", hostMode); } catch (e) { /* ignore */ }
    renderHosts();
  });
});
$("hostsearch").addEventListener("input", () => renderHosts());

function menu(anchor, items) { // items: [label, icon, fn, danger] or null for a separator
  document.querySelectorAll(".menu").forEach((m) => m.remove());
  const m = el("div", "menu");
  m.setAttribute("role", "menu");
  const close = () => { m.remove(); document.removeEventListener("mousedown", away, true); document.removeEventListener("keydown", esc, true); };
  const away = (e) => { if (!m.contains(e.target) && e.target !== anchor) close(); };
  const esc = (e) => { if (e.key === "Escape") { e.stopPropagation(); close(); anchor.focus(); } };
  items.forEach((it) => {
    if (!it) { m.appendChild(el("hr")); return; }
    const b = el("button", it[3] ? "danger" : "");
    b.type = "button";
    b.setAttribute("role", "menuitem");
    b.append(icon(it[1]), document.createTextNode(it[0]));
    b.addEventListener("click", () => { close(); anchor.focus(); it[2](); });
    m.appendChild(b);
  });
  anchor.parentNode.appendChild(m);
  document.addEventListener("mousedown", away, true);
  document.addEventListener("keydown", esc, true);
  m.querySelector("button").focus();
}

function hostCard(name, h) {
  const trusted = !!hostData.Trusted[name];
  const c = el("div", "card hostcard" + (h.agent ? "" : " dim"));
  const top = el("div", "top");
  const av = el("div", "avatar", initials(name));
  av.style.setProperty("--h", String(hashHue(name)));
  const main = el("div", "main");
  main.append(el("div", "name", name), el("div", "sub", addrOf(h)));
  main.title = h.description || "";
  main.tabIndex = 0;
  main.setAttribute("role", "button");
  main.setAttribute("aria-label", "Sửa host " + name);
  const mw = el("div", "menuwrap");
  const kb = el("button", "iconbtn");
  kb.type = "button";
  kb.setAttribute("aria-label", "Hành động cho " + name);
  kb.setAttribute("aria-haspopup", "menu");
  kb.appendChild(icon("more"));
  kb.addEventListener("click", (e) => {
    e.stopPropagation();
    menu(kb, [
      ["Sửa", "pencil", () => openHostDrawer(name, h).catch(fail)],
      ["Trust host key", "shieldcheck", () => trustHost(name)],
      ["Copy user@host", "copy", () => copyText((h.user ? h.user + "@" : "") + h.host)],
      null,
      ["Xóa", "trash", () => removeHost(name), true],
    ]);
  });
  mw.appendChild(kb);
  mw.addEventListener("keydown", (e) => e.stopPropagation());
  mw.addEventListener("click", (e) => e.stopPropagation());
  top.append(av, main, mw);
  const tags = el("div", "tags");
  tags.appendChild(el("span", "pill accent", h.profile || "standard"));
  const ag = el("span", "pill " + (h.agent ? "ok" : "neutral"));
  ag.append(el("span", "dot"), document.createTextNode(h.agent ? "agent" : "ẩn với agent"));
  tags.appendChild(ag);
  if (h.key) { const k = el("span", "pill neutral"); k.append(icon("key", 12), document.createTextNode(h.key)); tags.appendChild(k); }
  if (trusted) tags.appendChild(el("span", "pill ok", "host key đã tin"));
  else { // one click to the trust flow (fingerprint confirm + approval)
    const hk = el("button", "pill warn pillbtn");
    hk.type = "button";
    hk.title = "Bấm để kiểm tra fingerprint và tin host key";
    hk.append(icon("shieldcheck", 12), document.createTextNode("host key chưa tin · Trust"));
    hk.addEventListener("click", (e) => { e.stopPropagation(); trustHost(name).catch(fail); });
    tags.appendChild(hk);
  }
  c.append(top, tags);
  const open = () => openHostDrawer(name, h).catch(fail);
  c.addEventListener("click", open);
  c.addEventListener("keydown", (e) => { if ((e.key === "Enter" || e.key === " ") && e.target === main) { e.preventDefault(); open(); } });
  return c;
}
async function trustHost(name) {
  const o = await admin("trust", name);
  if (o) { ok(o); loadHosts().catch(fail); }
}
async function removeHost(name) {
  if (!(await confirmBox("Xóa host " + name + "?", "Cấu hình của host sẽ bị xóa khỏi hosts.toml. Key trong vault không bị ảnh hưởng.", { ok: "Xóa host", danger: true }))) return;
  const o = await admin("host-rm", name);
  if (o) { ok(o); loadHosts().catch(fail); }
}

function renderHosts() {
  const box = $("hostbox");
  box.replaceChildren();
  const q = $("hostsearch").value.trim().toLowerCase();
  const names = Object.keys(hostData.Hosts).sort().filter((n) => {
    const h = hostData.Hosts[n];
    return !q || (n + " " + addrOf(h) + " " + (h.description || "")).toLowerCase().includes(q);
  });
  if (!names.length) {
    const e = el("div", "empty");
    e.append(icon("server", 40), el("h3", null, q ? "Không có host khớp" : "Chưa có host nào"), el("p", null, q ? "Thử từ khóa khác." : 'Bấm "Thêm host" để cấu hình máy chủ đầu tiên cho agent.'));
    box.appendChild(e);
    return;
  }
  [["Agent dùng được", true], ["Ẩn với agent", false]].forEach(([label, flag]) => {
    const g = names.filter((n) => !!hostData.Hosts[n].agent === flag);
    if (!g.length) return;
    const gn = el("div", "groupname", label);
    gn.appendChild(el("span", "pill neutral", g.length));
    box.appendChild(gn);
    const grid = el("div", "hgrid" + (hostMode === "list" ? " list" : ""));
    g.forEach((n) => grid.appendChild(hostCard(n, hostData.Hosts[n])));
    box.appendChild(grid);
  });
}
async function loadHosts() {
  hostData = await call("GET", "/api/hosts");
  renderHosts();
}

function chipInput(initial, placeholder, label) {
  const wrap = el("div", "chips");
  const items = [];
  const inp = el("input");
  inp.placeholder = placeholder;
  inp.setAttribute("aria-label", label);
  inp.spellcheck = false;
  const add = (v) => {
    v = v.trim();
    if (!v || items.includes(v)) return;
    items.push(v);
    const c = el("span", "c", v);
    const x = el("button");
    x.type = "button";
    x.setAttribute("aria-label", "Bỏ " + v);
    x.appendChild(icon("x"));
    x.addEventListener("click", () => { items.splice(items.indexOf(v), 1); c.remove(); inp.focus(); });
    c.appendChild(x);
    wrap.insertBefore(c, inp);
  };
  (initial || []).forEach(add);
  inp.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); add(inp.value); inp.value = ""; }
    else if (e.key === "Backspace" && !inp.value && items.length) wrap.querySelector(".c:last-of-type button").click();
  });
  inp.addEventListener("blur", () => { add(inp.value); inp.value = ""; });
  wrap.addEventListener("click", () => inp.focus());
  wrap.appendChild(inp);
  return { node: wrap, input: inp, get: () => { add(inp.value); inp.value = ""; return items.slice(); } };
}

async function openHostDrawer(name, h) {
  let locked = false;
  const keys = await call("GET", "/api/keys").catch(() => { locked = !!(status && status.Locked); return []; });
  const layer = openLayer("drawer", name ? "Sửa host " + name : "Thêm host");
  const form = el("form");
  form.noValidate = true;
  form.id = "hostform";
  const mkInput = (type, val, ph) => { const i = el("input", "input"); i.type = type; i.value = val === undefined ? "" : val; if (ph) i.placeholder = ph; i.autocomplete = "off"; i.spellcheck = false; return i; };
  const iName = mkInput("text", name || "", "vd: web1");
  iName.readOnly = !!name;
  const iHost = mkInput("text", h ? h.host : "", "vd: 10.0.0.5 hoặc web1.example.com");
  const iPort = mkInput("number", h ? h.port || 22 : 22);
  iPort.min = "1"; iPort.max = "65535";
  const iUser = mkInput("text", h ? h.user : "", "vd: deploy");
  const sel = el("select", "select");
  sel.appendChild(el("option", null, "(không dùng key)")).value = "";
  keys.forEach((k) => { const n = k.split("\t")[0]; const o = el("option", null, n); o.value = n; sel.appendChild(o); });
  if (h && h.key && !keys.some((k) => k.split("\t")[0] === h.key)) { const o = el("option", null, h.key + (locked ? " (vault đang khóa)" : " (không tìm thấy)")); o.value = h.key; sel.appendChild(o); }
  sel.value = h ? h.key || "" : "";
  const iDesc = mkInput("text", h ? h.description : "", "Máy này dùng để làm gì");
  const fName = field("Tên", iName, name ? "Tên không đổi được sau khi tạo." : "Agent gọi host bằng tên này.");
  const fHost = field("Địa chỉ", iHost);
  const fPort = field("Port", iPort);
  const fUser = field("User", iUser);
  const row = el("div", "two");
  row.append(fHost, fPort);
  const fKey = field("Key trong vault", sel, "Chọn key hoặc mật khẩu đã lưu ở Kho khóa.");
  const fDesc = field("Mô tả", iDesc);

  const prof = el("div", "seg");
  prof.setAttribute("role", "radiogroup");
  prof.setAttribute("aria-label", "Profile");
  const cur = (h && h.profile) || "standard";
  ["readonly", "standard", "full"].forEach((p) => {
    const l = el("label");
    const r = el("input");
    r.type = "radio"; r.name = "profile"; r.value = p; r.checked = p === cur;
    l.append(r, el("span", null, p));
    prof.appendChild(l);
  });
  const fProf = el("div", "field");
  fProf.append(el("div", "lab", "Profile"), prof, el("div", "hint", "readonly chỉ đọc; standard cho lệnh thông thường; full gần như không giới hạn (vẫn qua duyệt)."));

  const sw = el("label", "switch");
  const cb = el("input");
  cb.type = "checkbox"; cb.checked = !!(h && h.agent);
  sw.append(cb, el("span", "track"), el("span", null, "Cho agent dùng host này"));
  const fAgent = el("div", "field");
  fAgent.append(sw, el("div", "hint", "Tắt thì agent không thấy host này."));

  const allow = chipInput(h && h.allow, "Gõ pattern rồi Enter", "Allow");
  const deny = chipInput(h && h.deny, "Gõ pattern rồi Enter", "Deny");
  const fAllow = el("div", "field"); fAllow.append(el("div", "lab", "Allow"), allow.node, el("div", "hint", "Lệnh khớp pattern được chạy không cần hỏi (nếu profile cho phép)."));
  const fDeny = el("div", "field"); fDeny.append(el("div", "lab", "Deny"), deny.node, el("div", "hint", "Lệnh khớp pattern bị chặn."));

  form.append(fName, row, fUser, fKey, fProf, fAgent, fDesc, fAllow, fDeny);
  layer.body.appendChild(form);
  let dirty = false;
  ["input", "change"].forEach((t) => form.addEventListener(t, () => { dirty = true; }));
  form.addEventListener("click", (e) => { if (e.target.closest(".chips button")) dirty = true; });
  layer.dirty = () => dirty;
  iName.setAttribute("data-autofocus", "");
  if (name) iHost.setAttribute("data-autofocus", "");

  const cancel = button("Hủy", "ghost");
  cancel.addEventListener("click", layer.close);
  const save = button("Lưu", "primary");
  save.type = "submit";
  save.setAttribute("form", form.id);
  layer.foot.append(cancel, save);

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    let bad = null;
    const need = (f, i, cond, msg) => { if (cond) { setErr(f, msg); bad = bad || i; } else setErr(f, ""); };
    need(fName, iName, !iName.value.trim(), "Nhập tên host");
    need(fHost, iHost, !iHost.value.trim(), "Nhập địa chỉ");
    const port = Number(iPort.value);
    need(fPort, iPort, !(Number.isInteger(port) && port >= 1 && port <= 65535), "Port 1–65535");
    if (bad) { bad.focus(); return; }
    const host = {
      host: iHost.value.trim(), port, user: iUser.value.trim(), key: sel.value,
      profile: (prof.querySelector("input:checked") || {}).value || "standard", agent: cb.checked,
      description: iDesc.value.trim(), allow: allow.get(), deny: deny.get(),
    };
    busy(save, async () => {
      const o = await admin("host-set", iName.value.trim(), { host });
      if (o) { ok(o); layer.close(); loadHosts().catch(fail); }
    });
  });
  layer.focusFirst();
}
$("hostadd").addEventListener("click", () => openHostDrawer("", null).catch(fail));
$("reload").addEventListener("click", (e) => busy(e.currentTarget, async () => { const o = await admin("reload", ""); if (o) { ok(o); refresh(); } }));

// ---- keychain ----
function shortFp(fp) { return fp.length > 26 ? fp.slice(0, 18) + "…" + fp.slice(-6) : fp; }
function usedBy(key) { return Object.keys(hostData.Hosts).filter((n) => hostData.Hosts[n].key === key).sort(); }

async function loadKeychain() {
  await loadStatus();
  hostData = await call("GET", "/api/hosts").catch(() => hostData);
  const hero = $("vaultcard");
  hero.replaceChildren();
  hero.className = "card vault-hero " + (status.Locked ? "locked" : "open");
  const big = el("div", "big");
  big.appendChild(icon(status.Locked ? "lock" : "unlock"));
  const txt = el("div", "txt");
  txt.append(el("h2", null, status.Locked ? "Vault đang khóa" : "Vault đang mở"),
    el("p", "muted", "Chế độ: " + (status.Passphrase ? "passphrase" : "keyring của hệ điều hành") + (status.VaultMissing ? " — chưa có vault, tạo key đầu tiên để khởi tạo." : "")));
  const ctl = el("div", "ctl");
  let pass = null;
  if (status.Locked && status.Passphrase) {
    pass = el("input", "input");
    pass.type = "password"; pass.placeholder = "Passphrase"; pass.autocomplete = "off";
    pass.setAttribute("aria-label", "Passphrase của vault");
    ctl.appendChild(pass);
  }
  const tg = button(status.Locked ? "Mở khóa" : "Khóa", status.Locked ? "primary" : "", status.Locked ? "unlock" : "lock");
  const doUnlock = () => busy(tg, async () => {
    if (status.Locked) {
      if (!status.Passphrase) toast("Hãy xác nhận trong hộp thoại của hệ điều hành…");
      await call("POST", "/api/unlock", { pass: pass ? pass.value : "" });
      ok("Đã mở khóa vault");
    } else {
      await call("POST", "/api/lock");
      ok("Đã khóa vault");
    }
    await refresh();
  });
  tg.addEventListener("click", doUnlock);
  if (pass) pass.addEventListener("keydown", (e) => { if (e.key === "Enter") doUnlock(); });
  ctl.appendChild(tg);
  hero.append(big, txt, ctl);

  const kl = $("keylist"), pl = $("pwlist");
  kl.replaceChildren();
  pl.replaceChildren();
  if (status.Locked) {
    kl.appendChild(emptyLine("Mở khóa vault để xem key."));
    pl.appendChild(emptyLine("Mở khóa vault để xem mật khẩu đã lưu."));
    return;
  }
  const entries = (await call("GET", "/api/keys")).map((k) => { const i = k.indexOf("\t"); return { name: k.slice(0, i), info: k.slice(i + 1) }; });
  const keys = entries.filter((e) => e.info !== "password");
  const pws = entries.filter((e) => e.info === "password");
  if (!keys.length) kl.appendChild(emptyLine("Chưa có key nào. Tạo hoặc import một key ở trên."));
  keys.forEach((k) => kl.appendChild(keyItem(k, false)));
  if (!pws.length) pl.appendChild(emptyLine("Chưa lưu mật khẩu nào."));
  pws.forEach((k) => pl.appendChild(keyItem(k, true)));
}
function emptyLine(t) { return el("div", "card list-item muted", t); }
function keyItem(k, isPw) {
  const c = el("div", "card list-item");
  const tb = el("div", "tilebox");
  tb.appendChild(icon(isPw ? "lock" : "key"));
  c.appendChild(tb);
  const main = el("div", "main");
  main.appendChild(el("div", "name", k.name));
  const sub = el("div", "sub");
  const users = usedBy(k.name);
  sub.textContent = users.length ? "Đang dùng bởi: " + users.join(", ") : "Chưa host nào dùng";
  main.appendChild(sub);
  c.appendChild(main);
  const tags = el("div", "tags");
  if (isPw) tags.appendChild(el("span", "pill neutral", "mật khẩu"));
  else {
    const sp = k.info.indexOf(" ");
    const type = sp < 0 ? k.info : k.info.slice(0, sp), fp = sp < 0 ? "" : k.info.slice(sp + 1);
    tags.appendChild(el("span", "pill accent", type.replace(/^ssh-/, "")));
    if (fp) {
      const f = el("span", "fp", shortFp(fp));
      f.title = fp;
      f.appendChild(copyBtn(fp, "Copy fingerprint"));
      tags.appendChild(f);
    }
  }
  c.appendChild(tags);
  const del = el("button", "iconbtn");
  del.type = "button";
  del.setAttribute("aria-label", "Xóa " + k.name);
  del.title = "Xóa";
  del.appendChild(icon("trash"));
  del.addEventListener("click", () => busy(del, async () => {
    const msg = users.length ? "Đang được dùng bởi: " + users.join(", ") + ". Các host này sẽ không đăng nhập được nữa." : "Hành động này không hoàn tác được.";
    if (!(await confirmBox("Xóa " + (isPw ? "mật khẩu " : "key ") + k.name + "?", msg, { ok: "Xóa", danger: true }))) return;
    const o = await admin("key-rm", k.name);
    if (o) { ok(o); loadKeychain().catch(fail); }
  }));
  c.appendChild(del);
  return c;
}

async function showPublicKey(name, pub) {
  const l = openLayer("modal", "Đã tạo key " + name);
  l.body.appendChild(el("p", null, "Thêm public key này vào ~/.ssh/authorized_keys của user trên server, rồi gán key cho host."));
  const box = el("div", "cmdbox");
  box.append(el("pre", "keycode", pub), copyBtn(pub, "Copy public key"));
  box.firstChild.style.paddingRight = "44px";
  l.body.appendChild(box);
  const done = button("Xong", "primary");
  done.addEventListener("click", l.close);
  const cp = button("Copy public key", "", "copy");
  cp.addEventListener("click", () => copyText(pub));
  l.foot.append(cp, done);
  done.focus();
}
$("keygen").addEventListener("click", async () => {
  try {
    const v = await askForm({ title: "Tạo key ed25519", desc: "Key mới được sinh và lưu trong vault; private key không rời khỏi daemon.", ok: "Tạo key", fields: [{ name: "name", label: "Tên key", placeholder: "vd: web1-agent", required: true }] });
    if (!v) return;
    const pub = await admin("key-gen", v.name.trim());
    if (!pub) return;
    loadKeychain().catch(fail);
    showPublicKey(v.name.trim(), pub);
  } catch (e) { fail(e); }
});
$("keyimport").addEventListener("click", async () => {
  try {
    const v = await askForm({
      title: "Import key", desc: "Chọn file private key (OpenSSH hoặc PEM). Key được chuẩn hóa rồi lưu vào vault.", ok: "Import",
      fields: [
        { name: "name", label: "Tên key", required: true },
        { name: "file", label: "File private key", type: "file", required: true, errmsg: "Chọn một file" },
        { name: "pass", label: "Passphrase của key", type: "password", hint: "Chỉ cần nếu key đang được bảo vệ." },
      ],
    });
    if (!v) return;
    const o = await admin("key-import", v.name.trim(), { key: await v.file.text(), keyPassphrase: v.pass });
    if (o) { ok(o); loadKeychain().catch(fail); }
  } catch (e) { fail(e); }
});
$("pwimport").addEventListener("click", async () => {
  try {
    const v = await askForm({
      title: "Lưu mật khẩu", desc: "Dùng khi server chỉ cho đăng nhập bằng mật khẩu. Nên ưu tiên key.", ok: "Lưu",
      fields: [{ name: "name", label: "Tên mục", required: true }, { name: "pw", label: "Mật khẩu", type: "password", required: true }],
    });
    if (!v) return;
    const o = await admin("key-import", v.name.trim(), { password: v.pw });
    if (o) { ok(o); loadKeychain().catch(fail); }
  } catch (e) { fail(e); }
});

// ---- known hosts ----
let khData = [];
async function loadKnownHosts() {
  khData = await call("GET", "/api/knownhosts");
  renderKnownHosts();
}
$("khsearch").addEventListener("input", () => renderKnownHosts());
function renderKnownHosts() {
  const box = $("khbox");
  box.replaceChildren();
  const q = $("khsearch").value.trim().toLowerCase();
  const rows = khData.filter((k) => !q || (k.host + " " + k.fingerprint + " " + (k.name || "")).toLowerCase().includes(q));
  if (!rows.length) {
    const e = el("div", "empty");
    e.append(icon("fingerprint", 40), el("h3", null, khData.length ? "Không có mục khớp" : "known_hosts đang trống"), el("p", null, "Host key được ghi lại khi bạn Trust một host ở màn hình Host."));
    box.appendChild(e);
    return;
  }
  const card = el("div", "card");
  const wrap = el("div", "tablewrap");
  const t = el("table");
  const hr = el("tr");
  ["Host", "Loại", "Fingerprint", "Host agentssh", ""].forEach((h) => hr.appendChild(el("th", null, h)));
  t.appendChild(el("thead")).appendChild(hr);
  const tb = el("tbody");
  rows.forEach((k) => {
    const tr = el("tr");
    tr.appendChild(el("td", "mono", k.host));
    const ty = el("td"); ty.appendChild(el("span", "pill accent", k.type.replace(/^ssh-/, ""))); tr.appendChild(ty);
    const fp = el("td", "mono nowrap", shortFp(k.fingerprint));
    fp.title = k.fingerprint;
    fp.appendChild(copyBtn(k.fingerprint, "Copy fingerprint"));
    tr.appendChild(fp);
    const nm = el("td");
    if (k.name) nm.appendChild(el("span", "pill ok", k.name)); else nm.appendChild(el("span", "muted", "-"));
    tr.appendChild(nm);
    const act = el("td");
    if (k.name) {
      const b = button("Trust lại", "", "shieldcheck");
      b.addEventListener("click", () => busy(b, async () => { const o = await admin("trust", k.name); if (o) { ok(o); loadKnownHosts().catch(fail); } }));
      act.appendChild(b);
    }
    tr.appendChild(act);
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  wrap.appendChild(t);
  card.appendChild(wrap);
  box.appendChild(card);
}

// ---- log & health ----
async function loadChecks() {
  const checks = await call("GET", "/api/doctor");
  const box = $("checks");
  box.replaceChildren();
  checks.forEach((c) => {
    const d = el("div", "card hcard " + (c.ok ? "ok" : "warn"));
    d.append(icon(c.ok ? "check" : "alert"), el("span", null, c.text));
    box.appendChild(d);
  });
}
$("rehealth").addEventListener("click", (e) => busy(e.currentTarget, loadChecks));

function decisionPill(d) {
  const cls = { allow: "ok", approved: "ok", denied: "bad", blocked: "bad", error: "bad", forbidden: "forbidden", timeout: "warn", ask: "accent" }[d] || "neutral";
  return el("span", "pill " + cls, d);
}
async function loadAudit() {
  const q = new URLSearchParams({ host: $("fhost").value.trim(), decision: $("fdecision").value, since: $("fsince").value, limit: PAGE, offset: auditOffset });
  const r = await call("GET", "/api/audit?" + q);
  const rows = $("auditrows");
  rows.replaceChildren();
  r.entries.forEach((e) => {
    const tr = el("tr", e.id ? "click" : "");
    const td = (cls, ...kids) => { const t = el("td", cls); kids.forEach((k) => t.append(k)); tr.appendChild(t); return t; };
    td("nowrap", new Date(e.time).toLocaleString());
    td("nowrap", e.id ? "#" + e.id : "");
    td("mono", e.host || "");
    td("", e.level ? levelPill(e.level) : "");
    td("", decisionPill(e.decision));
    td(e.exit === undefined ? "" : e.exit === 0 ? "exit0" : "exitn", e.exit === undefined ? "" : String(e.exit));
    const full = e.cmd + (e.note ? " (" + e.note + ")" : "");
    const c = td("cmdcell", full);
    c.title = full;
    if (e.id) {
      tr.tabIndex = 0;
      tr.setAttribute("role", "button");
      tr.setAttribute("aria-label", "Xem output #" + e.id);
      tr.addEventListener("click", () => showOutput(e.id).catch(fail));
      tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter") showOutput(e.id).catch(fail); });
    }
    rows.appendChild(tr);
  });
  if (!r.entries.length) {
    const tr = el("tr");
    const t = el("td", "muted", "Không có mục nào");
    t.colSpan = 7;
    tr.appendChild(t);
    rows.appendChild(tr);
  }
  $("pageinfo").textContent = r.total ? (auditOffset + 1) + "–" + Math.min(auditOffset + PAGE, r.total) + " / " + r.total : "Không có mục nào";
  $("prev").disabled = auditOffset === 0;
  $("next").disabled = auditOffset + PAGE >= r.total;
}
async function showOutput(id) {
  const l = openLayer("drawer", "Output #" + id);
  const bar = el("div", "toolbar");
  const sb = el("div", "searchbox grow");
  const grep = el("input", "input");
  grep.placeholder = "Lọc (regexp)";
  grep.setAttribute("aria-label", "Lọc output theo regexp");
  grep.spellcheck = false;
  sb.append(icon("search"), grep);
  const go = button("Lọc", "primary");
  bar.append(sb, go);
  const pre = el("pre", "outpre", "Đang tải…");
  l.body.append(bar, pre);
  let text = "";
  const load = async () => {
    const r = await call("GET", "/api/out/" + id + "?grep=" + encodeURIComponent(grep.value)).catch((e) => ({ text: e.message }));
    text = r.text || "";
    pre.textContent = text || "(trống)";
  };
  go.addEventListener("click", () => busy(go, load));
  grep.addEventListener("keydown", (e) => { if (e.key === "Enter") go.click(); });
  const cp = button("Copy", "", "copy");
  cp.addEventListener("click", () => copyText(text));
  const close = button("Đóng", "primary");
  close.addEventListener("click", l.close);
  l.foot.append(cp, close);
  grep.setAttribute("data-autofocus", "");
  l.focusFirst();
  await load();
}
const reload = () => { auditOffset = 0; loadAudit().catch(fail); };
$("ffilter").addEventListener("click", reload);
["fhost", "fsince"].forEach((i) => $(i).addEventListener("keydown", (e) => { if (e.key === "Enter") reload(); }));
$("fdecision").addEventListener("change", reload);
$("prev").addEventListener("click", () => { auditOffset = Math.max(0, auditOffset - PAGE); loadAudit().catch(fail); });
$("next").addEventListener("click", () => { auditOffset += PAGE; loadAudit().catch(fail); });

// ---- live updates ----
async function refresh() {
  try { await loadStatus(); await loadPending(); } catch (e) { fail(e); }
  if (view === "hosts") loadHosts().catch(fail);
  if (view === "keychain" && !document.activeElement.matches("input")) loadKeychain().catch(fail);
}
function conn(good) {
  $("conndot").className = "dot " + (good ? "ok" : "bad");
  $("conntext").textContent = good ? "Đã kết nối" : "Mất kết nối";
}
const es = new EventSource("/events");
let sseErrors = 0;
let esOpened = false;
es.onopen = () => { conn(true); if (esOpened) refresh(); esOpened = true; }; // resync what a drop missed
es.addEventListener("update", () => { sseErrors = 0; conn(true); refresh(); });
es.onerror = () => { conn(false); if (++sseErrors === 3) toast("Mất kết nối tới daemon agentssh", "error"); };
function route() { // #req=N focuses a request; #hosts, #keychain... deep-link a view
  const h = location.hash.slice(1);
  showView(Object.hasOwn(VIEWS, h) ? h : "approvals");
  if (h.startsWith("req=")) loadPending().catch(fail);
}
window.addEventListener("hashchange", route);
route();
refresh();
