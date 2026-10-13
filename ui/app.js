// FidoParole — UI. The decrypted vault stays in the Rust process; this page
// only ever holds entry fields without passwords. A password is fetched only
// when the user clicks "show", and copying happens in Rust.
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const st = {
  env: null,
  devices: [],
  selected: null,       // device path
  info: null,           // KeyInfo of the selected device
  vault: null,          // VaultView
  current: null,        // selected entry id
  revealed: false,
  copyTarget: null,
  copyInfo: null,
};

// ------------------------------------------------------------ helpers ----

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

let toastTimer;
/** Topmost open modal dialog (top layer), or the body. Toasts go there so a dialog can't cover them. */
function topHost() {
  const open = [...document.querySelectorAll("dialog[open]")].filter((d) => d.id !== "progress");
  return open.length ? open[open.length - 1] : document.body;
}

function toast(msg, bad = false) {
  const t = $("#toast");
  const host = topHost();
  if (t.parentElement !== host) host.appendChild(t);
  t.textContent = msg;
  t.className = bad ? "bad" : "";
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), bad ? 6000 : 3200);
}

/** Run a command; show the touch overlay with `wait` text while it runs.
 *  `steps`: texts for the "key-step" events Rust sends during two-touch
 *  operations, {1: [title, text, hint], 2: …, 3: …}. */
let keyBusy = false;
let keySteps = null;
function setProgress(step, text, hint) {
  const s = $("#progress-step");
  s.hidden = !step;
  s.textContent = step || "";
  $("#progress-text").textContent = text;
  $("#progress-hint").hidden = !hint;
  $("#progress-hint").textContent = hint || "";
}
/** Overlay text for a write to the key. With the PIN in memory no touch is
 *  needed; after a fingerprint unlock the key asks for the fingerprint again. */
function writePrompt(what) {
  if (st.vault?.pinSaved) return [{ text: `${what}…`, hint: "No touch needed. Don't unplug the key until this closes." }];
  return [{ step: "Fingerprint", text: `${what} — touch the fingerprint sensor when the key blinks.`,
    hint: "You unlocked with your fingerprint, so the key checks it again before it changes its storage." }];
}

/** Step texts for creating a vault credential on `who` ("your key" / "the target key"). */
function twoTouchSteps(who, label) {
  const on = label ? ` (${label})` : "";
  const sensor = "On a fingerprint key, touch the sensor.";
  return {
    1: ["Touch 1 of 2", `Touch ${who}${on} now — it is blinking.`, `This creates the vault credential. ${sensor}`],
    2: ["Touch 2 of 2", `Touch ${who} again — it is blinking.`, `This unlocks the key's hmac-secret, which encrypts the vault. ${sensor}`],
    3: ["Writing", `Writing the vault to ${who}…`, "No touch needed. Don't unplug the key until this closes."],
  };
}

async function call(cmd, args = {}, wait = null, steps = null) {
  const prog = $("#progress");
  if (wait) {
    // One key operation at a time (the overlay blocks clicks, this blocks shortcuts too).
    if (keyBusy) throw "another key operation is still running";
    keyBusy = true;
    keySteps = steps;
    // `wait`: a text, or { step, text, hint } for the overlay.
    if (typeof wait === "object") setProgress(wait.step, wait.text, wait.hint);
    else setProgress(null, wait, null);
    // A modal dialog of its own, so it sits above any open dialog.
    if (!prog.open) prog.showModal();
  }
  try {
    return await invoke(cmd, args);
  } catch (e) {
    const msg = String(e);
    if (msg.includes("vault is locked")) showLocked();
    throw msg;
  } finally {
    if (wait) { if (prog.open) prog.close(); keyBusy = false; keySteps = null; }
  }
}

async function attempt(fn) {
  try { await fn(); } catch (e) { toast(capital(e), true); }
}
const capital = (s) => (s ? String(s)[0].toUpperCase() + String(s).slice(1) : s);

function fmtTime(t) {
  if (!t) return "—";
  return new Date(t * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function confirmDlg(title, text, okText = "OK", danger = false) {
  return new Promise((res) => {
    const d = $("#dlg-confirm");
    $("#cf-title").textContent = title;
    $("#cf-text").textContent = text;
    const ok = $("#cf-ok");
    ok.textContent = okText;
    ok.className = danger ? "danger" : "primary";
    d.returnValue = "";
    d.onclose = () => res(d.returnValue === "ok");
    d.showModal();
  });
}

function message(title, text) {
  $("#msg-title").textContent = title;
  $("#msg-text").textContent = text;
  $("#dlg-message").showModal();
}

// ------------------------------------------------------------- views ----

function showLocked() {
  for (const p of pending.values()) clearTimeout(p.t);
  pending.clear();
  st.vault = null;
  st.current = null;
  hidePassword();
  $("#menus").hidden = $("#storage").hidden = $("#btn-save").hidden = $("#btn-lock").hidden = true;
  $("#side-keys").hidden = false;
  $("#side-entries").hidden = true;
  $("#view-locked").hidden = false;
  $("#view-choose").hidden = true;
  $("#view-vault").hidden = true;
  $("#entry-form").hidden = true;
  $("#search").value = "";
  $("#pin").value = "";
  renderKeyView();
}

function showVault(v) {
  st.vault = v;
  $("#pin").value = "";
  $("#menus").hidden = $("#btn-lock").hidden = false;
  $("#side-keys").hidden = true;
  $("#side-entries").hidden = false;
  $("#view-locked").hidden = true;
  $("#view-choose").hidden = true;
  $("#view-vault").hidden = false;
  renderVaultChrome();
  renderList();
  if (st.current && !v.entries.some((e) => e.id === st.current)) st.current = null;
  if (st.current) openEntry(st.current); else showEntryEmpty();
  if (v.notice) message("No saved data on the key", v.notice);
}

function renderVaultChrome() {
  const v = st.vault;
  if (!v) return;
  $("#dirty-banner").hidden = !v.dirty;
  $("#dirty-text").textContent = `Unsaved changes — they exist only in memory until you save them to the key. Auto-lock waits ${v.dirtyLockMinutes} min while changes are unsaved.`;
  $("#btn-save").hidden = !v.dirty;
  $("#vault-title").textContent = v.name;
  $("#vault-sub").textContent = `${v.entries.length} ${v.entries.length === 1 ? "entry" : "entries"} on ${v.device}. Select one on the left, or add a new entry.`;
  const s = $("#storage");
  s.hidden = !(v.max > 0);
  if (v.max > 0) {
    const pct = Math.min(100, (v.used / v.max) * 100);
    const m = s.querySelector(".meter");
    m.querySelector("i").style.width = pct + "%";
    m.classList.toggle("high", pct > 75);
    m.classList.toggle("full", pct > 92);
    s.querySelector("span").textContent = `${v.used.toLocaleString()} / ${v.max.toLocaleString()} B`;
  }
  $("#entry-count").textContent = v.entries.length ? "" : "No entries yet.";
}

// --------------------------------------------------------- devices ----

async function refreshDevices() {
  const list = $("#device-list");
  list.innerHTML = `<div class="device-empty">Looking for keys…</div>`;
  try {
    st.devices = await call("list_devices");
  } catch (e) {
    st.devices = [];
    list.innerHTML = `<div class="device-empty">${esc(capital(e))}</div>`;
    renderKeyView();
    return;
  }
  if (!st.devices.some((d) => d.path === st.selected && d.usable)) {
    st.selected = (st.devices.find((d) => d.usable) || {}).path || null;
    st.info = null;
  }
  renderDevices();
  if (st.selected) loadInfo(st.selected); else renderKeyView();
}

/** One line telling apart keys with the same product name. */
function devDetails(d) {
  const bits = [];
  if (d.serial) bits.push(`S/N ${d.serial}`);
  if (d.fwVersion) bits.push(`firmware ${d.fwVersion}`);
  if (d.aaguid) bits.push(`AAGUID ${d.aaguid.slice(0, 8)}…`);
  const tail = d.path.match(/hidraw\d+$/);
  if (tail) bits.push(tail[0]);
  return bits.join(" · ");
}

/** `opts.disabled`: grey out (e.g. the vault's own key as a copy target). */
function devButton(d, sel, opts = {}) {
  const mine = st.vault && d.path === st.vault.path;
  const badges = [
    d.fingerprint === true ? `<span class="badge bio">Fingerprint</span>` : d.fingerprint === false ? `<span class="badge">PIN only</span>` : "",
    mine ? `<span class="badge sc">This vault's key</span>` : "",
  ].join("");
  const details = devDetails(d);
  const title = [d.manufacturer, d.product, d.serial && `serial ${d.serial}`, d.aaguid && `AAGUID ${d.aaguid}`, d.fwVersion && `firmware ${d.fwVersion}`, d.path].filter(Boolean).join("\n");
  return `<button class="dev ${sel ? "sel" : ""}" data-path="${esc(d.path)}" title="${esc(title)}" ${d.usable && !opts.disabled ? "" : "disabled"}>
    <div class="top"><b>${esc(d.label)}</b><span class="badges">${badges}</span></div>
    ${details ? `<small class="mono">${esc(details)}</small>` : ""}
    ${d.usable ? "" : `<small>${esc(d.note)}</small>`}</button>`;
}

/** Blink the candidate keys; resolves to the path of the one touched. */
async function pickByTouch(paths) {
  if (!paths.length) { toast("No key to pick from", true); return null; }
  if (paths.length === 1) return paths[0];
  try {
    return await call("select_by_touch", { paths }, "Touch the key you want — all listed keys are blinking…");
  } catch (e) { toast(capital(e), true); return null; }
}

function renderDevices() {
  const list = $("#device-list");
  if (!st.devices.length) {
    list.innerHTML = `<div class="device-empty">No FIDO2 key found. Insert one and press refresh.</div>`;
  } else {
    list.innerHTML = st.devices.map((d) => devButton(d, d.path === st.selected)).join("");
  }
  list.querySelectorAll(".dev").forEach((b) => (b.onclick = () => {
    if (st.selected === b.dataset.path) return;
    st.selected = b.dataset.path;
    st.info = null;
    renderDevices();
    loadInfo(st.selected);
  }));
}

async function loadInfo(path) {
  renderKeyView();
  try {
    const info = await call("key_info", { path });
    if (st.selected === path) { st.info = info; renderKeyView(); }
  } catch (e) {
    if (st.selected === path) { st.info = { error: e }; renderKeyView(); }
  }
}

function renderKeyView() {
  const dev = st.devices.find((d) => d.path === st.selected);
  $("#no-key").hidden = !!dev;
  $("#key-view").hidden = !dev;
  if (!dev) return;
  $("#kv-name").textContent = dev.label;
  const tb = $("#kv-transport");
  tb.className = "badge hid";
  tb.textContent = "USB HID";
  const i = st.info;
  const chips = $("#kv-chips");
  const prob = $("#kv-problem");
  const actions = $("#kv-actions");
  if (!i) { chips.innerHTML = `<span class="chip">Reading key…</span>`; prob.hidden = true; actions.hidden = true; return; }
  if (i.error) { chips.innerHTML = ""; prob.textContent = capital(i.error); prob.hidden = false; actions.hidden = true; return; }
  const chip = (ok, text) => `<span class="chip ${ok ? "ok" : "no"}">${ok ? "✓" : "✕"} ${esc(text)}</span>`;
  chips.innerHTML = [
    chip(i.hmacSecret, "hmac-secret"),
    chip(i.largeBlob, i.largeBlob ? `largeBlob · ${i.maxLargeBlob.toLocaleString()} bytes` : "largeBlob"),
    chip(i.hasPin, i.hasPin ? "PIN set" : "No PIN set"),
    i.hasUv ? chip(true, "Fingerprint") : "",
    i.pinRetries >= 0 ? `<span class="chip">${i.pinRetries} PIN retries left</span>` : "",
    dev.serial ? `<span class="chip">S/N ${esc(dev.serial)}</span>` : "",
    i.fwVersion ? `<span class="chip">Firmware ${esc(i.fwVersion)}</span>` : "",
    i.aaguid ? `<span class="chip" title="AAGUID (identifies the key model)">AAGUID ${esc(i.aaguid)}</span>` : "",
  ].join("");
  let problem = "";
  if (!i.hmacSecret || !i.largeBlob) problem = "This key lacks hmac-secret or largeBlob support, so it cannot hold a vault.";
  else if (!i.hasPin) problem = "Set a FIDO2 PIN on this key first — with any FIDO2 management tool (for example Token2 Key Manager).";
  prob.textContent = problem;
  prob.hidden = !problem;
  actions.hidden = !!problem;
  $("#lbl-uv").hidden = !i.hasUv;
  if (!i.hasUv) $("#use-uv").checked = false;
  $("#lbl-pin").hidden = $("#use-uv").checked;
}

function pinArg() {
  if ($("#use-uv").checked) return null;
  const p = $("#pin").value;
  return p || null;
}

async function doUnlock() {
  if (!st.selected) return;
  if (!$("#use-uv").checked && !$("#pin").value) { toast("Enter the key's PIN", true); $("#pin").focus(); return; }
  await attempt(async () => {
    const r = await call("unlock", { path: st.selected, pin: pinArg() }, "Touch your key when it blinks…");
    $("#pin").value = "";
    if (r.kind === "opened") { showVault(r.vault); toast("Vault unlocked"); }
    else showChoose(r);
  });
}

async function doCreate() {
  if (!st.selected) return;
  if (!$("#use-uv").checked && !$("#pin").value) { toast("Enter the key's PIN above first", true); $("#pin").focus(); return; }
  const name = $("#new-name").value.trim();
  if (!name) { toast("Give the vault a name", true); return; }
  await attempt(async () => {
    const dev = st.devices.find((d) => d.path === st.selected);
    const v = await call("create_vault", { path: st.selected, pin: pinArg(), name },
      "Creating the vault — your key will blink twice; touch it each time.", twoTouchSteps("your key", dev?.label));
    showVault(v);
    toast("Vault created on the key");
  });
}

function showChoose(r) {
  $("#view-locked").hidden = true;
  $("#view-choose").hidden = false;
  $("#choose-device").textContent = `${r.device} holds several vaults. Pick the one to open.`;
  const list = $("#choose-list");
  list.innerHTML = r.vaults.map((v) => `<button data-i="${v.index}"><b>${esc(v.name)}</b><span class="hint">${v.size == null ? "empty" : v.size.toLocaleString() + " bytes"}</span></button>`).join("");
  list.querySelectorAll("button").forEach((b) => (b.onclick = () => attempt(async () => showVault(await call("choose_vault", { index: +b.dataset.i })))));
}

// --------------------------------------------------------- entries ----

function initials(t) {
  const w = (t || "?").trim();
  return esc((w.match(/[A-Za-z0-9]/) || ["?"])[0].toUpperCase());
}

function renderList() {
  const v = st.vault;
  if (!v) return;
  const q = $("#search").value.trim().toLowerCase();
  const items = v.entries.filter((e) => !q || [e.title, e.username, e.url].some((f) => (f || "").toLowerCase().includes(q)));
  const list = $("#entry-list");
  list.innerHTML = items.map((e) => `<button class="ent ${e.id === st.current ? "sel" : ""}" data-id="${esc(e.id)}">
      <span class="av">${initials(e.title)}</span>
      <span class="t"><b>${esc(e.title || "(untitled)")}</b><small>${esc(e.username || e.url || "")}</small></span></button>`).join("");
  if (q && !items.length) list.innerHTML = `<div class="device-empty">No matches.</div>`;
  list.querySelectorAll(".ent").forEach((b) => (b.onclick = () => openEntry(b.dataset.id)));
}

function showEntryEmpty() {
  hidePassword();
  $("#entry-form").hidden = true;
  $("#entry-empty").hidden = false;
}

async function openEntry(id) {
  await flushPending();
  hidePassword();
  st.current = id;
  renderList();
  let e;
  try { e = await call("get_entry", { id }); } catch (err) { toast(capital(err), true); return; }
  $("#entry-empty").hidden = true;
  $("#entry-form").hidden = false;
  $("#f-title").value = e.title;
  $("#f-username").value = e.username;
  $("#f-url").value = e.url;
  $("#f-notes").value = e.notes;
  setPasswordPlaceholder(e.hasPassword);
  $("#f-meta").textContent = e.created ? `Created ${fmtTime(e.created)} · Modified ${fmtTime(e.modified)}` : `Modified ${fmtTime(e.modified)}`;
}

function setPasswordPlaceholder(has) {
  const p = $("#f-password");
  p.dataset.has = has ? "1" : "";
  p.placeholder = has ? "●●●●●●●●●●●●  (hidden — type to replace)" : "No password — type one or generate";
}

/** Remove a revealed password from the page. */
function hidePassword() {
  const p = $("#f-password");
  p.value = "";
  p.type = "password";
  st.revealed = false;
}

async function toggleReveal() {
  if (!st.current) return;
  if (st.revealed) { hidePassword(); return; }
  await attempt(async () => {
    const pw = await call("reveal_password", { id: st.current });
    const p = $("#f-password");
    p.type = "text";
    p.value = pw;
    st.revealed = true;
  });
}

// Debounced per-field updates to Rust.
const pending = new Map();
function queueUpdate(field, value) {
  const id = st.current;
  if (!id) return;
  const key = id + "|" + field;
  clearTimeout(pending.get(key)?.t);
  const t = setTimeout(() => sendUpdate(id, field, value, key), 300);
  pending.set(key, { t, id, field, value });
}
async function sendUpdate(id, field, value, key) {
  pending.delete(key);
  if (!st.vault) return;
  try {
    const sm = await call("update_entry", { id, field, value });
    const e = st.vault?.entries.find((x) => x.id === id);
    if (e) Object.assign(e, sm);
    if (field === "password") setPasswordPlaceholder(!!value);
    if (st.vault && !st.vault.dirty) { st.vault.dirty = true; renderVaultChrome(); }
    if (field === "title" || field === "username" || field === "url") renderList();
    $("#f-meta").textContent = $("#f-meta").textContent.replace(/Modified .*/, "Modified " + fmtTime(sm.modified));
  } catch (e) { toast(capital(e), true); }
}
async function flushPending() {
  const jobs = [...pending.entries()].map(([key, p]) => { clearTimeout(p.t); return sendUpdate(p.id, p.field, p.value, key); });
  await Promise.all(jobs);
}

async function newEntry() {
  await attempt(async () => {
    await flushPending();
    const id = await call("new_entry");
    st.current = id;
    $("#search").value = "";
    showVault(await call("vault_view"));
    $("#f-title").select();
    $("#f-title").focus();
  });
}

async function deleteEntry() {
  if (!st.current) return;
  const title = $("#f-title").value || "this entry";
  if (!(await confirmDlg("Delete entry?", `“${title}” is removed now and disappears from the key on the next save.`, "Delete", true))) return;
  await attempt(async () => {
    await call("delete_entry", { id: st.current });
    st.current = null;
    showVault(await call("vault_view"));
  });
}

async function generate() {
  if (!st.current) return;
  await attempt(async () => {
    await flushPending();
    const opts = {
      length: +$("#gen-len").value,
      upper: $("#gen-upper").checked, lower: $("#gen-lower").checked,
      digits: $("#gen-digits").checked, symbols: $("#gen-symbols").checked,
    };
    await call("generate_password", { id: st.current, opts });
    setPasswordPlaceholder(true);
    if (st.revealed) { st.revealed = false; await toggleReveal(); } else hidePassword();
    st.vault.dirty = true;
    renderVaultChrome();
    toast("New password generated");
  });
}

async function copyField(field) {
  if (!st.current) return;
  await attempt(async () => {
    await flushPending();
    const secs = await call("copy_field", { id: st.current, field });
    toast(`${capital(field === "url" ? "URL" : field)} copied — the clipboard clears in ${secs} s`);
  });
}

async function saveToKey() {
  if (!st.vault) return;
  try {
    await flushPending();
    const v = await call("save_to_key", {}, ...writePrompt("Saving to the key"));
    st.vault = v;
    renderVaultChrome();
    toast("Saved to the key");
  } catch (e) {
    const msg = capital(e);
    // Problems that reconnecting can't fix: say so plainly.
    if (/does not fit|storage is full|wrong PIN|blocked|locked or switched/i.test(msg)) { toast(msg, true); return; }
    if (await confirmDlg("Couldn't save to the key", `${msg}. If the key was unplugged or the computer slept, reconnect to it and save again — the vault is still open in memory.`, "Reconnect…")) {
      openReconnect(true);
    }
  }
}

// ------------------------------------------------------- reconnect ----

let rcTarget = null, rcSaveAfter = false;

async function openReconnect(saveAfter = false) {
  if (!st.vault) return;
  rcSaveAfter = saveAfter;
  rcTarget = null;
  $("#rc-err").textContent = "";
  $("#dlg-reconnect").showModal();
  await refreshReconnectDevices();
}

async function refreshReconnectDevices() {
  const box = $("#rc-devices");
  box.innerHTML = `<div class="device-empty">Looking for keys…</div>`;
  try { st.devices = await call("list_devices"); } catch (e) { box.innerHTML = `<div class="device-empty">${esc(capital(e))}</div>`; return; }
  const usable = st.devices.filter((d) => d.usable);
  if (!usable.some((d) => d.path === rcTarget)) {
    rcTarget = usable.some((d) => d.path === st.vault?.path) ? st.vault.path : usable.length === 1 ? usable[0].path : null;
  }
  renderReconnectDevices();
}

function renderReconnectDevices() {
  const box = $("#rc-devices");
  box.innerHTML = st.devices.length
    ? st.devices.map((d) => devButton(d, d.path === rcTarget)).join("")
    : `<div class="device-empty">No key found — insert the key this vault is on and press refresh.</div>`;
  box.querySelectorAll(".dev").forEach((b) => (b.onclick = (ev) => {
    ev.preventDefault();
    rcTarget = b.dataset.path;
    renderReconnectDevices();
  }));
}

async function submitReconnect(ev) {
  ev.preventDefault();
  if (ev.submitter?.value === "cancel") { $("#dlg-reconnect").close(); return; }
  if (!rcTarget) { $("#rc-err").textContent = "Pick the key this vault is on."; return; }
  $("#rc-err").textContent = "";
  try {
    await flushPending();
    const r = await call("reconnect", { path: rcTarget }, st.vault?.pinSaved
      ? "Reconnecting — touch the key when it blinks…"
      : { step: "Fingerprint", text: "Reconnecting — touch the fingerprint sensor when the key blinks.", hint: "The key checks your fingerprint before it gives out the vault's secret." });
    $("#dlg-reconnect").close();
    st.vault = r.vault;
    renderVaultChrome();
    if (r.changedOnKey) {
      message("The vault on the key has changed",
        "Since this vault was opened here, a different version was saved to the key (from another computer, or another window). " +
        "What you see here is now treated as unsaved: “Save to key” replaces the key's version with this one. " +
        "To keep the key's version instead, lock without saving and unlock again.");
    } else {
      toast(`Reconnected to ${r.vault.device}`);
      if (rcSaveAfter && r.vault.dirty) await saveToKey();
    }
  } catch (e) { $("#rc-err").textContent = capital(e); }
}

async function lockNow() {
  await flushPending().catch(() => {});
  if (st.vault?.dirty && !(await confirmDlg("Discard unsaved changes?", "The vault has changes that are not on the key yet. Locking wipes them from memory.", "Lock anyway", true))) return;
  await attempt(async () => { await call("lock"); showLocked(); toast("Locked"); });
}

// ---------------------------------------------------------- backups ----

function openExport() {
  $("#ex-pass").value = $("#ex-pass2").value = "";
  $("#ex-err").textContent = "";
  $("#dlg-export").showModal();
}

async function submitExport(ev) {
  ev.preventDefault();
  if (ev.submitter?.value === "cancel") { $("#dlg-export").close(); return; }
  const a = $("#ex-pass").value, b = $("#ex-pass2").value;
  if ([...a].length < 10) { $("#ex-err").textContent = "Use at least 10 characters."; return; }
  if (a !== b) { $("#ex-err").textContent = "The passphrases differ."; return; }
  $("#dlg-export").close();
  await attempt(async () => {
    await flushPending();
    const path = await call("export_backup", { passphrase: a }, "Encrypting the backup…");
    $("#ex-pass").value = $("#ex-pass2").value = "";
    if (path) message("Backup written", `Encrypted backup saved to\n${path}`);
  });
}

let importFile = null;
function openImport() {
  importFile = null;
  $("#im-file").textContent = "No file selected";
  $("#im-pass").value = "";
  $("#im-err").textContent = "";
  $("#dlg-import").showModal();
}

async function submitImport(ev) {
  ev.preventDefault();
  if (ev.submitter?.value === "cancel") { $("#dlg-import").close(); return; }
  if (!importFile) { $("#im-err").textContent = "Choose a backup file."; return; }
  const pass = $("#im-pass").value;
  if (!pass) { $("#im-err").textContent = "Enter the backup passphrase."; return; }
  const replace = document.querySelector('input[name="im-mode"]:checked').value === "replace";
  if (replace && !(await confirmDlg("Replace the vault?", "All current entries are replaced by the backup's entries.", "Replace", true))) return;
  $("#im-err").textContent = "";
  try {
    await flushPending();
    const msg = await call("import_backup", { file: importFile, passphrase: pass, replace }, "Decrypting the backup…");
    $("#dlg-import").close();
    $("#im-pass").value = "";
    st.current = null;
    showVault(await call("vault_view"));
    message("Backup imported", `${msg} Save to the key to keep it.`);
  } catch (e) {
    $("#im-err").textContent = capital(e);
  }
}

// ---------------------------------------------------- copy to key ----

async function openCopy() {
  st.copyTarget = null;
  st.copyInfo = null;
  $("#cp-name").value = st.vault?.name || "";
  $("#cp-pin").value = "";
  $("#cp-err").textContent = "";
  $("#cp-info").textContent = "";
  $("#dlg-copy").showModal();
  await refreshCopyDevices();
}

async function refreshCopyDevices() {
  const box = $("#cp-devices");
  box.innerHTML = `<div class="device-empty">Looking for keys…</div>`;
  try { st.devices = await call("list_devices"); } catch (e) { box.innerHTML = `<div class="device-empty">${esc(capital(e))}</div>`; return; }
  renderCopyDevices();
}

function renderCopyDevices() {
  const box = $("#cp-devices");
  box.innerHTML = st.devices.length
    ? st.devices.map((d) => devButton(d, d.path === st.copyTarget, { disabled: d.path === st.vault?.path })).join("")
    : `<div class="device-empty">No key found — insert the target key and press refresh.</div>`;
  box.querySelectorAll(".dev").forEach((b) => (b.onclick = (ev) => { ev.preventDefault(); selectCopyTarget(b.dataset.path); }));
}

async function selectCopyTarget(path) {
  st.copyTarget = path;
  st.copyInfo = null;
  renderCopyDevices();
  $("#cp-info").textContent = "Reading key…";
  try {
    const i = await call("key_info", { path });
    if (st.copyTarget !== path) return;
    st.copyInfo = i;
    $("#cp-info").textContent =
      !i.hmacSecret || !i.largeBlob ? "This key lacks hmac-secret / largeBlob and cannot hold a vault."
      : !i.hasPin ? "Set a FIDO2 PIN on this key first."
      : `largeBlob capacity ${i.maxLargeBlob.toLocaleString()} bytes`;
  } catch (e) { $("#cp-info").textContent = capital(e); }
}

async function submitCopy(ev) {
  ev.preventDefault();
  if (ev.submitter?.value === "cancel") { $("#dlg-copy").close(); return; }
  const i = st.copyInfo;
  const pin = $("#cp-pin").value, name = $("#cp-name").value.trim();
  if (!st.copyTarget || !i) { $("#cp-err").textContent = "Pick the target key."; return; }
  if (!i.hmacSecret || !i.largeBlob || !i.hasPin) { $("#cp-err").textContent = "This key can't hold a vault."; return; }
  if (!pin) { $("#cp-err").textContent = "Enter the target key's PIN."; return; }
  if (!name) { $("#cp-err").textContent = "Give the vault a name."; return; }
  $("#cp-err").textContent = "";
  try {
    await flushPending();
    const dev = st.devices.find((d) => d.path === st.copyTarget);
    const label = await call("copy_to_key", { path: st.copyTarget, pin, name },
      "Copying — the target key will blink twice; touch it each time.", twoTouchSteps("the target key", dev?.label));
    $("#cp-pin").value = "";
    $("#dlg-copy").close();
    $("#cd-text").textContent = `The vault is now also stored on ${label}. The two keys hold independent copies: later changes are saved only to the key this session uses.`;
    const d = $("#dlg-copied");
    d.returnValue = "";
    d.onclose = () => attempt(async () => {
      const v = await call("finish_copy", { switch: d.returnValue === "switch" });
      if (v) { showVault(v); toast("Now using the new key"); }
    });
    d.showModal();
  } catch (e) { $("#cp-err").textContent = capital(e); }
}

function openDelete() {
  if (!st.vault) return;
  const v = st.vault, n = v.entries.length;
  $("#dv-name").textContent = `“${v.name}”`;
  $("#dv-count").textContent = n === 1 ? "1 entry" : `${n} entries`;
  $("#dv-device").textContent = v.device;
  $("#dv-dirty").hidden = !v.dirty;
  $("#dv-ack").checked = false;
  $("#dv-confirm").value = "";
  $("#dv-confirm-lbl").textContent = v.name ? `Type the vault name (${v.name}) to confirm` : "Type DELETE to confirm";
  $("#dv-err").textContent = "";
  updateDeleteOk();
  $("#dlg-delete").showModal();
}

function updateDeleteOk() {
  $("#dv-ok").disabled = !($("#dv-ack").checked && st.vault && $("#dv-confirm").value.trim() === (st.vault.name || "DELETE"));
}

async function submitDelete(ev) {
  ev.preventDefault();
  if (ev.submitter?.value === "cancel") { $("#dlg-delete").close(); return; }
  updateDeleteOk();
  if ($("#dv-ok").disabled) return;
  $("#dlg-delete").close();
  await attempt(async () => {
    await call("delete_vault", {}, ...writePrompt("Removing the vault from the key"));
    showLocked();
    refreshDevices();
    message("Vault deleted", "The vault was removed from the key.");
  });
}

function openSettings() {
  $("#set-lock").value = String(st.vault?.lockMinutes ?? st.env.lockMinutes ?? 5);
  const d = $("#dlg-settings");
  d.returnValue = "";
  d.onclose = () => {
    if (d.returnValue !== "ok") return;
    const m = +$("#set-lock").value;
    attempt(async () => {
      await call("set_lock_minutes", { minutes: m });
      if (st.vault) st.vault.lockMinutes = m;
      toast(`Auto-lock after ${m} min`);
    });
  };
  d.showModal();
}

/** Read the environment and show the administrator warning on Windows. */
async function applyEnv() {
  st.env = await invoke("env_info");
  const needAdmin = !!st.env.needsAdmin;
  $("#admin-text").textContent = needAdmin
    ? "FidoParole is not running as administrator. Windows only lets elevated programs talk to FIDO2 keys over USB HID, so no key can be used. Restart the app as administrator."
    : "";
  $("#btn-elevate").hidden = !needAdmin;
  $("#admin-banner").hidden = !needAdmin;
}

// ------------------------------------------------------------- wire ----

function wireMenus() {
  $$(".menu").forEach((m) => {
    m.querySelector(".menu-btn").onclick = (ev) => {
      ev.stopPropagation();
      const open = m.classList.contains("open");
      $$(".menu").forEach((x) => x.classList.remove("open"));
      if (!open) m.classList.add("open");
    };
  });
  document.addEventListener("click", () => $$(".menu").forEach((x) => x.classList.remove("open")));
  const actions = {
    save: saveToKey, lock: lockNow, settings: openSettings, "delete-vault": openDelete, reconnect: () => openReconnect(),
    "copy-key": openCopy, export: openExport, import: openImport,
  };
  $$("[data-mi]").forEach((b) => (b.onclick = () => { $$(".menu").forEach((x) => x.classList.remove("open")); actions[b.dataset.mi]?.(); }));
}

function wire() {
  wireMenus();
  $("#btn-refresh").onclick = refreshDevices;
  $("#btn-touch").onclick = async () => {
    const p = await pickByTouch(st.devices.filter((d) => d.usable).map((d) => d.path));
    if (p && p !== st.selected) { st.selected = p; st.info = null; renderDevices(); loadInfo(p); }
  };
  $("#cp-touch").onclick = async () => {
    const p = await pickByTouch(st.devices.filter((d) => d.usable && d.path !== st.vault?.path).map((d) => d.path));
    if (p) selectCopyTarget(p);
  };
  $("#rc-touch").onclick = async () => {
    const p = await pickByTouch(st.devices.filter((d) => d.usable).map((d) => d.path));
    if (p) { rcTarget = p; renderReconnectDevices(); }
  };
  $("#btn-settings").onclick = openSettings;
  $("#btn-elevate").onclick = () => attempt(async () => {
    if (st.vault?.dirty && !(await confirmDlg("Discard unsaved changes?", "Restarting closes the vault.", "Restart anyway", true))) return;
    await call("restart_as_admin");
  });
  $("#form-unlock").onsubmit = (e) => { e.preventDefault(); doUnlock(); };
  $("#form-create").onsubmit = (e) => { e.preventDefault(); doCreate(); };
  $("#use-uv").onchange = () => { $("#lbl-pin").hidden = $("#use-uv").checked; };
  $("#btn-choose-cancel").onclick = () => attempt(async () => { await call("cancel_choose"); showLocked(); });

  $("#btn-save").onclick = saveToKey;
  $("#btn-save2").onclick = saveToKey;
  $("#btn-lock").onclick = lockNow;
  $("#btn-new").onclick = newEntry;
  $("#search").oninput = renderList;
  $("#btn-del-entry").onclick = deleteEntry;
  $("#btn-reveal").onclick = toggleReveal;
  $("#btn-gen").onclick = generate;
  $("#gen-len").oninput = () => ($("#gen-len-out").textContent = $("#gen-len").value);
  $$("[data-copy]").forEach((b) => (b.onclick = () => copyField(b.dataset.copy)));
  for (const f of ["title", "username", "url", "notes", "password"]) {
    $("#f-" + f).addEventListener("input", (e) => {
      // A hidden password is only replaced by what is typed; emptying the field
      // again does not erase the stored one (reveal it first to clear it).
      if (f === "password" && !st.revealed && e.target.value === "") {
        const key = st.current + "|password";
        clearTimeout(pending.get(key)?.t);
        pending.delete(key);
        return;
      }
      queueUpdate(f, e.target.value);
    });
  }

  $("#form-export").addEventListener("submit", submitExport);
  $("#form-import").addEventListener("submit", submitImport);
  $("#im-pick").onclick = () => attempt(async () => {
    const f = await call("pick_backup_file");
    if (f) { importFile = f; $("#im-file").textContent = f; }
  });
  $("#form-copy").addEventListener("submit", submitCopy);
  $("#cp-refresh").onclick = refreshCopyDevices;
  $("#form-reconnect").addEventListener("submit", submitReconnect);
  $("#rc-refresh").onclick = refreshReconnectDevices;
  $("#form-delete").addEventListener("submit", submitDelete);
  $("#dv-ack").onchange = updateDeleteOk;
  $("#dv-confirm").oninput = updateDeleteOk;
  $("#dv-export").onclick = () => { $("#dlg-delete").close(); openExport(); };

  // Keyboard shortcuts: Ctrl/Cmd+S save, Ctrl/Cmd+L lock, Ctrl/Cmd+F search.
  document.addEventListener("keydown", (e) => {
    if (!(e.ctrlKey || e.metaKey) || !st.vault) return;
    const k = e.key.toLowerCase();
    if (k === "s") { e.preventDefault(); saveToKey(); }
    else if (k === "l") { e.preventDefault(); lockNow(); }
    else if (k === "f") { e.preventDefault(); $("#search").focus(); }
  });

  // Activity ping (throttled) keeps the Rust idle timer from locking an active session.
  let lastPing = 0;
  const ping = () => {
    const now = Date.now();
    if (st.vault && now - lastPing > 15000) { lastPing = now; invoke("activity").catch(() => {}); }
  };
  ["keydown", "mousedown", "mousemove", "wheel"].forEach((ev) => document.addEventListener(ev, ping, { passive: true }));

  // Don't leave a revealed password on screen when the window loses focus.
  window.addEventListener("blur", () => { if (st.revealed) hidePassword(); });

  listen("vault-locked", (e) => { showLocked(); refreshDevices(); toast(e.payload || "Locked"); });
  listen("clipboard-cleared", () => toast("Clipboard cleared"));
  listen("key-step", (e) => { const s = keySteps?.[e.payload]; if (s) setProgress(...s); });
  // The touch overlay can't be dismissed with Esc; the key operation keeps running.
  $("#progress").addEventListener("cancel", (e) => e.preventDefault());
}

async function init() {
  wire();
  await applyEnv();
  // A demo session (debug builds) or a reload while unlocked lands straight in the vault.
  try { showVault(await invoke("vault_view")); } catch { showLocked(); }
  refreshDevices();
}

init();
