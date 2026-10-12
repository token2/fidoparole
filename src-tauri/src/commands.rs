//! Tauri commands. The decrypted vault lives only here, in Rust memory.
//!
//! The webview is given the entry list and entry fields *without* passwords.
//! A password crosses into the page only when the user asks to see it
//! (`reveal_password`) or while typing a new one. Copying a password to the
//! clipboard happens in Rust, so it never enters the page at all.

use crate::fido::{self, DeviceEntry, KeyInfo, VaultCredential};
use crate::keyops::{self, Unlocked};
use crate::vault::{self, Entry, GenOptions, VaultData};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

type R<T> = Result<T, String>;

pub const CLIPBOARD_CLEAR_SECS: u64 = 20;

// ------------------------------------------------------------------ state ---

pub struct Session {
    /// HID path of the key the vault came from.
    path: String,
    device: String,
    cred: VaultCredential,
    /// Kept while unlocked so "Save to key" doesn't ask again; wiped on lock.
    pin: Option<Zeroizing<String>>,
    data: VaultData,
    dirty: bool,
    /// Bumped on every change; a save only clears `dirty` if nothing changed
    /// while the key was being written.
    edits: u64,
    used: usize,
    max: u64,
    /// Size of this vault's blob as last read from / written to the key.
    blob_len: usize,
    /// Set when the credential had no data on the key at unlock time.
    notice: Option<String>,
    /// AAGUID of the key, so Reconnect never sends the PIN to another model.
    aaguid: String,
    /// SHA-256 of the blob as last read from / written to the key, to notice
    /// a vault that was changed elsewhere while this one was disconnected.
    blob_hash: Option<[u8; 32]>,
}

/// Persisted preferences (settings.json in the app's config directory).
/// Nothing secret: only the auto-lock time.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub lock_minutes: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { lock_minutes: 5 }
    }
}

pub struct Inner {
    session: Option<Session>,
    pending: Option<(Unlocked, Option<Zeroizing<String>>)>,
    copied: Option<(Unlocked, Option<Zeroizing<String>>)>,
    devices: Vec<DeviceEntry>,
    last_activity: Instant,
    lock_minutes: u64,
    /// Bumped on every copy, so a stale clear-timer doesn't wipe a newer copy.
    clip_gen: u64,
    /// SHA-256 of what we last put on the clipboard, so we only ever clear our own text.
    clip_hash: Option<[u8; 32]>,
    settings: Settings,
    settings_path: Option<PathBuf>,
}

impl Default for Inner {
    fn default() -> Self {
        Inner {
            session: None, pending: None, copied: None, devices: vec![], last_activity: Instant::now(),
            lock_minutes: 5, clip_gen: 0, clip_hash: None, settings: Settings::default(), settings_path: None,
        }
    }
}

impl Inner {
    fn save_settings(&self) {
        if let Some(p) = &self.settings_path {
            if let Some(dir) = p.parent() { let _ = std::fs::create_dir_all(dir); }
            if let Ok(json) = serde_json::to_vec_pretty(&self.settings) { let _ = std::fs::write(p, json); }
        }
    }
}

/// Load settings.json at startup.
pub fn load_settings(app: &AppHandle) {
    let path = app.path().app_config_dir().ok().map(|d| d.join("settings.json"));
    let settings: Settings = path.as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let state = app.state::<AppState>();
    if let Ok(mut g) = state.0.lock() {
        g.lock_minutes = settings.lock_minutes.clamp(1, 120);
        g.settings = settings;
        g.settings_path = path;
    };
}

/// Tell the page which step of a two-touch operation the key is on.
fn step_emitter(app: &AppHandle) -> impl Fn(keyops::Step) + '_ {
    move |s| { let _ = app.emit("key-step", s as u8); }
}

fn need_path(path: String) -> R<String> {
    if path.is_empty() { Err("pick a security key first".into()) } else { Ok(path) }
}

/// While there are unsaved changes, auto-lock waits this many times longer.
const DIRTY_LOCK_FACTOR: u64 = 4;

pub struct AppState(pub Mutex<Inner>);

impl AppState {
    fn lock(&self) -> R<std::sync::MutexGuard<'_, Inner>> {
        let mut g = self.0.lock().map_err(|_| "internal state lock poisoned".to_string())?;
        g.last_activity = Instant::now();
        Ok(g)
    }
}

/// Clipboard owned for the whole process: on X11/Wayland the copied text
/// lives only as long as its owner.
pub struct Clip(pub Mutex<Option<arboard::Clipboard>>);

/// Serialises all key I/O: two largeBlob writes interleaving would corrupt
/// the key's shared largeBlob array.
static KEY_IO: Mutex<()> = Mutex::new(());

/// Run blocking key I/O off the async runtime, one operation at a time.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> R<T> + Send + 'static) -> R<T> {
    tauri::async_runtime::spawn_blocking(move || {
        let _io = KEY_IO.lock().unwrap_or_else(|p| p.into_inner());
        f()
    })
    .await
    .map_err(|e| e.to_string())?
}

fn sha(s: &str) -> [u8; 32] {
    sha_bytes(s.as_bytes())
}

fn sha_bytes(b: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(b).into()
}

fn pin_ref(p: &Option<Zeroizing<String>>) -> Option<&str> {
    p.as_ref().map(|s| s.as_str()).filter(|s| !s.is_empty())
}

fn to_pin(pin: Option<String>) -> Option<Zeroizing<String>> {
    pin.filter(|p| !p.is_empty()).map(Zeroizing::new)
}

// -------------------------------------------------------------------- DTOs --

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvInfo {
    elevated: bool,
    os: &'static str,
    version: &'static str,
    clipboard_clear_secs: u64,
    /// Windows without elevation: FIDO HID is not reachable.
    needs_admin: bool,
    lock_minutes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    id: String,
    title: String,
    username: String,
    url: String,
    modified: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultView {
    name: String,
    device: String,
    /// HID path of the vault's key, so device lists can mark it.
    path: String,
    dirty: bool,
    used: usize,
    max: u64,
    lock_minutes: u64,
    dirty_lock_minutes: u64,
    notice: Option<String>,
    entries: Vec<Summary>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    id: String,
    title: String,
    username: String,
    url: String,
    notes: String,
    created: i64,
    modified: i64,
    has_password: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultChoice {
    index: usize,
    name: String,
    size: Option<usize>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum UnlockResult {
    Opened { vault: VaultView },
    Choose { device: String, vaults: Vec<VaultChoice> },
}

fn summary(e: &Entry) -> Summary {
    Summary { id: e.id.clone(), title: e.title.clone(), username: e.username.clone(), url: e.url.clone(), modified: e.modified }
}

fn view(s: &Session, lock_minutes: u64) -> VaultView {
    let mut entries: Vec<Summary> = s.data.entries.iter().map(summary).collect();
    entries.sort_by_key(|e| e.title.to_lowercase());
    VaultView {
        name: s.cred.name.clone(), device: s.device.clone(), path: s.path.clone(), dirty: s.dirty, used: s.used, max: s.max,
        lock_minutes, dirty_lock_minutes: lock_minutes * DIRTY_LOCK_FACTOR, notice: s.notice.clone(), entries,
    }
}

fn session(g: &mut Inner) -> R<&mut Session> {
    g.session.as_mut().ok_or_else(|| "the vault is locked".to_string())
}

fn entry<'a>(s: &'a mut Session, id: &str) -> R<&'a mut Entry> {
    s.data.entries.iter_mut().find(|e| e.id == id).ok_or_else(|| "entry not found".to_string())
}

fn device_label(devs: &[DeviceEntry], path: &str) -> String {
    devs.iter().find(|d| d.path == path).map(|d| d.label.clone()).unwrap_or_else(|| path.to_string())
}

/// Check that `index` exists and its blob decrypts, without consuming anything,
/// so a failure leaves the candidates in place for another try.
fn check_openable(u: &Unlocked, index: usize) -> R<()> {
    let (cred, blob) = u.creds.get(index).ok_or("no such vault")?;
    if let Some(b) = blob { vault::open(b, &cred.hmac_secret)?; }
    Ok(())
}

/// Turn a chosen credential + blob into a live session.
fn open_session(g: &mut Inner, u: Unlocked, index: usize, pin: Option<Zeroizing<String>>) -> R<VaultView> {
    let Unlocked { path, mut creds, used, max, aaguid } = u;
    if index >= creds.len() { return Err("no such vault".into()); }
    let (cred, blob) = creds.swap_remove(index);
    let blob_hash = blob.as_deref().map(sha_bytes);
    let (data, blob_len, notice, dirty) = match blob {
        Some(b) => (vault::open(&b, &cred.hmac_secret)?, b.len(), None, false),
        // The credential exists but the key holds no data for it: a vault that
        // was never saved, or a largeBlob array that was lost or reset.
        None => (VaultData::default(), 0, Some(
            "This key holds no saved data for this vault, so it opens empty. If you expected entries here, \
             don't save: restore them with Backup → Import, or open the vault from another key.".to_string()), false),
    };
    let device = device_label(&g.devices, &path);
    g.session = Some(Session { path, device, cred, pin, data, dirty, edits: if dirty { 1 } else { 0 }, used, max, blob_len, notice, aaguid, blob_hash });
    g.pending = None;
    let lm = g.lock_minutes;
    Ok(view(g.session.as_ref().unwrap(), lm))
}

/// Clear the clipboard, but only if it still holds the text we put there.
fn clear_clipboard_if(app: &AppHandle, hash: [u8; 32]) {
    let clip = app.state::<Clip>();
    let Ok(mut g) = clip.0.lock() else { return };
    if let Some(c) = g.as_mut() {
        if c.get_text().map(|cur| sha(&Zeroizing::new(cur)) == hash).unwrap_or(false) {
            let _ = c.clear();
        }
    };
}

fn wipe_session(app: &AppHandle, g: &mut Inner) {
    g.session = None; // vault data, hmac-secret, largeBlob key and PIN are zeroized on drop
    g.pending = None;
    g.copied = None;
    g.clip_gen += 1;
    if let Some(h) = g.clip_hash.take() { clear_clipboard_if(app, h); }
}

/// Background idle watcher: locks the vault after `lock_minutes` without any
/// command or UI activity — unless there are unsaved changes.
pub fn start_idle_watch(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(10));
        let state = app.state::<AppState>();
        let Ok(mut g) = state.0.lock() else { continue };
        let idle_for = g.last_activity.elapsed();
        let limit = Duration::from_secs(g.lock_minutes * 60);
        let has_secrets = g.session.is_some() || g.pending.is_some() || g.copied.is_some();
        let dirty = g.session.as_ref().map(|s| s.dirty).unwrap_or(false);
        // Unsaved changes get a longer grace period, but never stay open forever.
        let due = if dirty { idle_for > limit * DIRTY_LOCK_FACTOR as u32 } else { idle_for > limit };
        if has_secrets && due {
            wipe_session(&app, &mut g);
            drop(g);
            let msg = if dirty { "Locked after inactivity — unsaved changes were discarded" } else { "Locked after inactivity" };
            let _ = app.emit("vault-locked", msg);
        }
    });
}

// --------------------------------------------------------------- commands ---

#[tauri::command]
pub fn env_info(state: State<'_, AppState>) -> R<EnvInfo> {
    let g = state.lock()?;
    let elevated = crate::platform::is_elevated();
    Ok(EnvInfo {
        elevated,
        os: std::env::consts::OS,
        version: env!("CARGO_PKG_VERSION"),
        clipboard_clear_secs: CLIPBOARD_CLEAR_SECS,
        needs_admin: cfg!(windows) && !elevated,
        lock_minutes: g.lock_minutes,
    })
}

/// Windows: restart this program elevated (UAC prompt); FIDO HID needs it.
#[tauri::command]
pub fn restart_as_admin(app: AppHandle) -> R<()> {
    #[cfg(windows)]
    {
        use windows::core::PCWSTR;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let w = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let (verb, file) = (w("runas"), w(&exe.to_string_lossy()));
        let r = unsafe { ShellExecuteW(None, PCWSTR(verb.as_ptr()), PCWSTR(file.as_ptr()), PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL) };
        if (r.0 as isize) <= 32 {
            return Err("the elevated restart was cancelled".into());
        }
        app.exit(0);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Err("only needed on Windows".into())
    }
}

#[tauri::command]
pub async fn list_devices(state: State<'_, AppState>) -> R<Vec<DeviceEntry>> {
    let devs = blocking(fido::list_devices).await?;
    state.lock()?.devices = devs.clone();
    Ok(devs)
}

/// Blink all the given keys; returns the path of the one touched (30 s).
#[tauri::command]
pub async fn select_by_touch(paths: Vec<String>) -> R<String> {
    blocking(move || fido::select_by_touch(&paths, 30_000)).await
}

#[tauri::command]
pub async fn key_info(path: String) -> R<KeyInfo> {
    blocking(move || fido::key_info(&path)).await
}

#[tauri::command]
pub async fn unlock(state: State<'_, AppState>, path: String, pin: Option<String>) -> R<UnlockResult> {
    let path = need_path(path)?;
    let pin = to_pin(pin);
    let p2 = pin.clone();
    let u = blocking(move || keyops::unlock(&path, pin_ref(&p2))).await?;
    let mut g = state.lock()?;
    if u.creds.is_empty() {
        return Err("no vault on this key yet — create one".into());
    }
    if u.creds.len() == 1 {
        return Ok(UnlockResult::Opened { vault: open_session(&mut g, u, 0, pin)? });
    }
    let vaults = u.creds.iter().enumerate().map(|(i, (c, b))| VaultChoice {
        index: i,
        name: if c.name.is_empty() { format!("Vault {}", i + 1) } else { c.name.clone() },
        size: b.as_ref().map(|b| b.len()),
    }).collect();
    let device = device_label(&g.devices, &u.path);
    g.pending = Some((u, pin));
    Ok(UnlockResult::Choose { device, vaults })
}

#[tauri::command]
pub fn choose_vault(state: State<'_, AppState>, index: usize) -> R<VaultView> {
    let mut g = state.lock()?;
    check_openable(&g.pending.as_ref().ok_or("nothing to choose from")?.0, index)?;
    let (u, pin) = g.pending.take().unwrap();
    open_session(&mut g, u, index, pin)
}

#[tauri::command]
pub fn cancel_choose(state: State<'_, AppState>) -> R<()> {
    state.lock()?.pending = None;
    Ok(())
}

#[tauri::command]
pub async fn create_vault(app: AppHandle, state: State<'_, AppState>, path: String, pin: Option<String>, name: String) -> R<VaultView> {
    let name = name.trim().to_string();
    if name.is_empty() { return Err("give the vault a name".into()); }
    if name.len() > fido::MAX_NAME_BYTES { return Err(format!("use a vault name of at most {} bytes", fido::MAX_NAME_BYTES)); }
    let pin = to_pin(pin);
    let p2 = pin.clone();
    let path = need_path(path)?;
    let u = blocking(move || keyops::create(&path, pin_ref(&p2), &name, &VaultData::default(), &step_emitter(&app))).await?;
    let mut g = state.lock()?;
    open_session(&mut g, u, 0, pin)
}

#[tauri::command]
pub fn vault_view(state: State<'_, AppState>) -> R<VaultView> {
    let mut g = state.lock()?;
    let lm = g.lock_minutes;
    Ok(view(session(&mut g)?, lm))
}

#[tauri::command]
pub fn get_entry(state: State<'_, AppState>, id: String) -> R<EntryView> {
    let mut g = state.lock()?;
    let e = entry(session(&mut g)?, &id)?;
    Ok(EntryView {
        id: e.id.clone(), title: e.title.clone(), username: e.username.clone(), url: e.url.clone(),
        notes: e.notes.clone(), created: e.created, modified: e.modified, has_password: !e.password.is_empty(),
    })
}

/// The one place a stored password is handed to the page — on "show".
#[tauri::command]
pub fn reveal_password(state: State<'_, AppState>, id: String) -> R<String> {
    let mut g = state.lock()?;
    Ok(entry(session(&mut g)?, &id)?.password.clone())
}

#[tauri::command]
pub fn new_entry(state: State<'_, AppState>) -> R<String> {
    let mut g = state.lock()?;
    let s = session(&mut g)?;
    let e = Entry::new("New entry");
    let id = e.id.clone();
    s.data.entries.push(e);
    s.dirty = true;
    s.edits += 1;
    Ok(id)
}

#[tauri::command]
pub fn update_entry(state: State<'_, AppState>, id: String, field: String, value: String) -> R<Summary> {
    let value = Zeroizing::new(value);
    let mut g = state.lock()?;
    let s = session(&mut g)?;
    let e = entry(s, &id)?;
    let slot = match field.as_str() {
        "title" => &mut e.title,
        "username" => &mut e.username,
        "password" => &mut e.password,
        "url" => &mut e.url,
        "notes" => &mut e.notes,
        _ => return Err("unknown field".into()),
    };
    if *slot != *value {
        use zeroize::Zeroize;
        slot.zeroize();
        slot.push_str(&value);
        e.touch();
        let sm = summary(e);
        s.dirty = true;
        s.edits += 1;
        return Ok(sm);
    }
    Ok(summary(e))
}

#[tauri::command]
pub fn delete_entry(state: State<'_, AppState>, id: String) -> R<()> {
    let mut g = state.lock()?;
    let s = session(&mut g)?;
    let before = s.data.entries.len();
    s.data.entries.retain(|e| e.id != id);
    if s.data.entries.len() != before { s.dirty = true; s.edits += 1; }
    Ok(())
}

/// Generate a password straight into the entry; the page never sees it
/// unless the user reveals it.
#[tauri::command]
pub fn generate_password(state: State<'_, AppState>, id: String, opts: GenOptions) -> R<()> {
    let mut g = state.lock()?;
    let s = session(&mut g)?;
    let e = entry(s, &id)?;
    use zeroize::Zeroize;
    e.password.zeroize();
    e.password = vault::generate_password(&opts);
    e.touch();
    s.dirty = true;
    s.edits += 1;
    Ok(())
}

/// Copy a field to the system clipboard from Rust, then clear it after
/// CLIPBOARD_CLEAR_SECS if it still holds the same text.
#[tauri::command]
pub fn copy_field(app: AppHandle, state: State<'_, AppState>, clip: State<'_, Clip>, id: String, field: String) -> R<u64> {
    let (text, gen) = {
        let mut g = state.lock()?;
        g.clip_gen += 1;
        let gen = g.clip_gen;
        // Clear an earlier copy of ours before replacing it.
        if let Some(h) = g.clip_hash.take() { clear_clipboard_if(&app, h); }
        let e = entry(session(&mut g)?, &id)?;
        let t = match field.as_str() {
            "username" => e.username.clone(),
            "password" => e.password.clone(),
            "url" => e.url.clone(),
            _ => return Err("unknown field".into()),
        };
        (Zeroizing::new(t), gen)
    };
    if text.is_empty() { return Err("nothing to copy".into()); }
    {
        let mut c = clip.0.lock().map_err(|_| "clipboard lock poisoned")?;
        if c.is_none() { *c = arboard::Clipboard::new().ok(); }
        let cb = c.as_mut().ok_or("no clipboard available")?;
        // Keep secrets out of clipboard history / cloud sync where the OS supports it.
        let set = cb.set();
        #[cfg(windows)]
        let set = { use arboard::SetExtWindows; set.exclude_from_history().exclude_from_cloud() };
        #[cfg(target_os = "macos")]
        let set = { use arboard::SetExtApple; set.exclude_from_history() };
        #[cfg(all(unix, not(target_os = "macos")))]
        let set = { use arboard::SetExtLinux; set.exclude_from_history() };
        set.text(text.to_string()).map_err(|e| format!("clipboard: {e}"))?;
    }
    let hash = sha(&text);
    if let Ok(mut g) = state.0.lock() { g.clip_hash = Some(hash); }
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(CLIPBOARD_CLEAR_SECS));
        let still_ours = app.state::<AppState>().0.lock().map(|mut g| {
            let ours = g.clip_gen == gen;
            if ours { g.clip_hash = None; }
            ours
        }).unwrap_or(false);
        if still_ours {
            clear_clipboard_if(&app, hash);
            let _ = app.emit("clipboard-cleared", ());
        }
    });
    Ok(CLIPBOARD_CLEAR_SECS)
}

#[tauri::command]
pub async fn save_to_key(state: State<'_, AppState>) -> R<VaultView> {
    // Rough per-entry overhead libfido2 adds in the largeBlob array
    // (CBOR map, AES-GCM nonce + tag, origSize, deflate framing).
    const ENTRY_OVERHEAD: usize = 64;
    let (path, lbk, cred_id, pin, blob, edits, budget) = {
        let mut g = state.lock()?;
        let s = session(&mut g)?;
        let blob = vault::seal(&s.data, &s.cred.hmac_secret)?;
        // Space available to this vault = capacity minus what the other
        // credentials' entries (and the array's checksum) already take.
        let mine = if s.blob_len > 0 { s.blob_len + ENTRY_OVERHEAD } else { 0 };
        let budget = if s.max > 0 && s.used > 0 { Some((s.max as usize).saturating_sub(s.used.saturating_sub(mine))) }
                     else if s.max > 0 { Some(s.max as usize) } else { None };
        (s.path.clone(), s.cred.large_blob_key.clone(), s.cred.cred_id.clone(), s.pin.clone(), blob, s.edits, budget)
    };
    if let Some(b) = budget {
        if blob.len() + ENTRY_OVERHEAD > b {
            return Err(format!(
                "the vault ({} bytes) does not fit: about {} bytes of the key's largeBlob storage are free for it — remove some entries or notes",
                blob.len(), b.saturating_sub(ENTRY_OVERHEAD)
            ));
        }
    }
    let len = blob.len();
    let hash = sha_bytes(&blob);
    let used = blocking(move || keyops::write(&path, &lbk, &blob, pin_ref(&pin))).await?;
    let mut g = state.lock()?;
    let lm = g.lock_minutes;
    let s = session(&mut g)?;
    if s.cred.cred_id != cred_id {
        return Err("the vault was locked or switched while saving".into());
    }
    if used > 0 { s.used = used; }
    s.blob_len = len;
    s.blob_hash = Some(hash);
    s.notice = None;
    // Edits made while the key was busy are not on the key yet.
    if s.edits == edits { s.dirty = false; }
    Ok(view(s, lm))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconnectResult {
    vault: VaultView,
    /// The vault data on the key differs from what this session last read or saved.
    changed_on_key: bool,
}

/// Re-attach the open vault to its key after the key was unplugged, the
/// computer slept, or the device path changed. One touch.
#[tauri::command]
pub async fn reconnect(state: State<'_, AppState>, path: String) -> R<ReconnectResult> {
    let path = need_path(path)?;
    let (pin, aaguid, cred_id, secret) = {
        let mut g = state.lock()?;
        let s = session(&mut g)?;
        (s.pin.clone(), s.aaguid.clone(), s.cred.cred_id.clone(), s.cred.hmac_secret.clone())
    };
    let p2 = path.clone();
    let id2 = cred_id.clone();
    let rc = blocking(move || keyops::reconnect(&p2, pin_ref(&pin), &aaguid, &id2, &secret)).await?;
    let mut g = state.lock()?;
    let label = device_label(&g.devices, &path);
    let lm = g.lock_minutes;
    let s = session(&mut g)?;
    if s.cred.cred_id != cred_id {
        return Err("the vault was locked or switched while reconnecting".into());
    }
    let new_hash = rc.blob.as_deref().map(sha_bytes);
    let changed_on_key = new_hash != s.blob_hash;
    s.path = path;
    s.device = label;
    s.cred.large_blob_key = rc.cred.large_blob_key.clone();
    s.used = rc.used;
    s.max = rc.max;
    s.blob_len = rc.blob.as_ref().map(|b| b.len()).unwrap_or(0);
    s.blob_hash = new_hash;
    if changed_on_key {
        // What is in memory no longer matches the key: treat it as unsaved.
        s.dirty = true;
        s.edits += 1;
    }
    Ok(ReconnectResult { vault: view(s, lm), changed_on_key })
}

#[tauri::command]
pub fn lock(app: AppHandle, state: State<'_, AppState>) -> R<()> {
    let mut g = state.lock()?;
    wipe_session(&app, &mut g);
    Ok(())
}

/// Called (throttled) by the page on keyboard/mouse activity.
#[tauri::command]
pub fn activity(state: State<'_, AppState>) -> R<()> {
    state.lock().map(|_| ())
}

#[tauri::command]
pub fn set_lock_minutes(state: State<'_, AppState>, minutes: u64) -> R<()> {
    let mut g = state.lock()?;
    g.lock_minutes = minutes.clamp(1, 120);
    g.settings.lock_minutes = g.lock_minutes;
    g.save_settings();
    Ok(())
}

// --------------------------------------------------------------- backups ----

#[tauri::command]
pub async fn export_backup(state: State<'_, AppState>, passphrase: String) -> R<Option<String>> {
    let pass = Zeroizing::new(passphrase);
    let (data, name) = {
        let mut g = state.lock()?;
        let s = session(&mut g)?;
        (s.data.clone(), s.cred.name.clone())
    };
    let Some(file) = rfd::AsyncFileDialog::new()
        .set_file_name(format!("{}.t2vault", name.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_")))
        .add_filter("FidoParole backup", &["t2vault"])
        .save_file()
        .await
    else {
        return Ok(None);
    };
    let path = file.path().to_path_buf();
    blocking(move || {
        let bytes = vault::export_backup(&data, &pass)?;
        std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
        Ok(Some(path.display().to_string()))
    })
    .await
}

#[tauri::command]
pub async fn pick_backup_file() -> R<Option<String>> {
    Ok(rfd::AsyncFileDialog::new()
        .add_filter("FidoParole backup", &["t2vault"])
        .pick_file()
        .await
        .map(|f| f.path().display().to_string()))
}

#[tauri::command]
pub async fn import_backup(state: State<'_, AppState>, file: String, passphrase: String, replace: bool) -> R<String> {
    let pass = Zeroizing::new(passphrase);
    let other = blocking(move || {
        let bytes = std::fs::read(&file).map_err(|e| e.to_string())?;
        vault::import_backup(&bytes, &pass)
    })
    .await?;
    let mut g = state.lock()?;
    let s = session(&mut g)?;
    let msg = if replace {
        let n = other.entries.len();
        s.data = other;
        format!("Replaced the vault with the {n} entries from the backup.")
    } else {
        let (a, u) = s.data.merge(&other);
        format!("Merged the backup: {a} added, {u} updated.")
    };
    s.dirty = true;
    s.edits += 1;
    Ok(msg)
}

/// Copy the in-memory vault to another key: new credential there, the same
/// entries encrypted under that key's own hmac-secret (two touches).
#[tauri::command]
pub async fn copy_to_key(app: AppHandle, state: State<'_, AppState>, path: String, pin: Option<String>, name: String) -> R<String> {
    let name = name.trim().to_string();
    if name.is_empty() { return Err("give the vault a name".into()); }
    if name.len() > fido::MAX_NAME_BYTES { return Err(format!("use a vault name of at most {} bytes", fido::MAX_NAME_BYTES)); }
    let path = need_path(path)?;
    let pin = to_pin(pin);
    let data = {
        let mut g = state.lock()?;
        let s = session(&mut g)?;
        if s.path == path { return Err("pick a different key than the one this vault is on".into()); }
        s.data.clone()
    };
    let p2 = pin.clone();
    let path2 = path.clone();
    let app2 = app.clone();
    let u = blocking(move || keyops::create(&path2, pin_ref(&p2), &name, &data, &step_emitter(&app2))).await?;
    let mut g = state.lock()?;
    let label = device_label(&g.devices, &path);
    g.copied = Some((u, pin));
    Ok(label)
}

/// After a copy: optionally make the new key this session's key.
#[tauri::command]
pub fn finish_copy(state: State<'_, AppState>, switch: bool) -> R<Option<VaultView>> {
    let mut g = state.lock()?;
    if !switch { g.copied = None; return Ok(None); }
    let Some((u, _)) = g.copied.as_ref() else { return Ok(None) };
    check_openable(u, 0)?;
    let (u, pin) = g.copied.take().unwrap();
    // The copy holds everything that was in memory, unsaved edits included,
    // so the new session starts clean.
    open_session(&mut g, u, 0, pin).map(Some)
}

#[tauri::command]
pub async fn delete_vault(app: AppHandle, state: State<'_, AppState>) -> R<()> {
    let (path, cred_id, lbk, pin) = {
        let mut g = state.lock()?;
        let s = session(&mut g)?;
        (s.path.clone(), s.cred.cred_id.clone(), s.cred.large_blob_key.clone(), s.pin.clone())
    };
    blocking(move || keyops::delete(&path, &cred_id, &lbk, pin_ref(&pin))).await?;
    let mut g = state.lock()?;
    wipe_session(&app, &mut g);
    Ok(())
}

/// Debug builds only: FIDOPAROLE_DEMO=1 opens a throw-away in-memory vault so
/// the UI can be reviewed without a key. Saving it fails by design.
#[cfg(debug_assertions)]
pub fn demo_session(state: &AppState) {
    let mut data = VaultData::default();
    for (t, u, url) in [
        ("Proton Mail", "emin@example.com", "https://mail.proton.me"),
        ("GitHub", "token2", "https://github.com/login"),
        ("Swiss bank e-banking", "123456", "https://ebanking.example.ch"),
        ("Router admin", "admin", "http://192.168.1.1"),
    ] {
        let mut e = Entry::new(t);
        e.username = u.into();
        e.url = url.into();
        e.password = vault::generate_password(&GenOptions::default());
        data.entries.push(e);
    }
    let mut g = state.0.lock().unwrap();
    g.session = Some(Session {
        path: "demo".into(),
        device: "Token2 PIN+ (demo, no key)".into(),
        cred: VaultCredential { cred_id: vec![], name: "Personal".into(), hmac_secret: Zeroizing::new([0; 32]), large_blob_key: Zeroizing::new(vec![0; 32]) },
        pin: None, data, dirty: false, edits: 0, used: 1380, max: 4096, blob_len: 1300, notice: None,
        aaguid: String::new(), blob_hash: None,
    });
}
