//! Thin libfido2 wrapper for the vault: discoverable credential with
//! hmac-secret + largeBlobKey, assertion with an hmac-secret salt, and
//! largeBlob read / write / remove.
//!
//! FIDO HID only, on every platform. Windows opens raw FIDO HID only for an
//! elevated process, so there the app must run as administrator. Smart-card /
//! NFC (PC/SC) entries are not listed.
//!
//! Every call opens the device, does one thing and closes it again, so a key
//! can be swapped between operations (needed for "copy vault to another key").

#![allow(non_camel_case_types)]

use serde::Serialize;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use zeroize::Zeroizing;

#[repr(C)] struct fido_dev_t { _p: [u8; 0] }
#[repr(C)] struct fido_dev_info_t { _p: [u8; 0] }
#[repr(C)] struct fido_cbor_info_t { _p: [u8; 0] }
#[repr(C)] struct fido_cred_t { _p: [u8; 0] }
#[repr(C)] struct fido_assert_t { _p: [u8; 0] }

type fido_opt_t = c_int;
const FIDO_OPT_OMIT: fido_opt_t = 0;
const FIDO_OPT_TRUE: fido_opt_t = 2;

const FIDO_OK: c_int = 0;
const COSE_ES256: c_int = -7;
const FIDO_EXT_HMAC_SECRET: c_int = 0x01;
const FIDO_EXT_CRED_PROTECT: c_int = 0x02;
const FIDO_EXT_LARGEBLOB_KEY: c_int = 0x04;
const FIDO_CRED_PROT_UV_REQUIRED: c_int = 0x03;

extern "C" {
    fn fido_init(flags: c_int);
    fn fido_set_log_handler(handler: Option<extern "C" fn(*const c_char)>);
    fn fido_strerr(n: c_int) -> *const c_char;

    fn fido_dev_info_new(n: usize) -> *mut fido_dev_info_t;
    fn fido_dev_info_free(list: *mut *mut fido_dev_info_t, n: usize);
    fn fido_dev_info_manifest(list: *mut fido_dev_info_t, ilen: usize, olen: *mut usize) -> c_int;
    fn fido_dev_info_ptr(list: *const fido_dev_info_t, i: usize) -> *const fido_dev_info_t;
    fn fido_dev_info_path(di: *const fido_dev_info_t) -> *const c_char;
    fn fido_dev_info_manufacturer_string(di: *const fido_dev_info_t) -> *const c_char;
    fn fido_dev_info_product_string(di: *const fido_dev_info_t) -> *const c_char;
    fn fido_dev_info_vendor(di: *const fido_dev_info_t) -> i16;
    fn fido_dev_info_product(di: *const fido_dev_info_t) -> i16;

    fn fido_dev_new() -> *mut fido_dev_t;
    fn fido_dev_free(dev: *mut *mut fido_dev_t);
    fn fido_dev_open(dev: *mut fido_dev_t, path: *const c_char) -> c_int;
    fn fido_dev_close(dev: *mut fido_dev_t) -> c_int;
    fn fido_dev_is_fido2(dev: *const fido_dev_t) -> bool;
    fn fido_dev_has_pin(dev: *const fido_dev_t) -> bool;
    fn fido_dev_has_uv(dev: *const fido_dev_t) -> bool;
    fn fido_dev_get_retry_count(dev: *mut fido_dev_t, n: *mut c_int) -> c_int;

    fn fido_cbor_info_new() -> *mut fido_cbor_info_t;
    fn fido_cbor_info_free(ci: *mut *mut fido_cbor_info_t);
    fn fido_dev_get_cbor_info(dev: *mut fido_dev_t, ci: *mut fido_cbor_info_t) -> c_int;
    fn fido_cbor_info_extensions_ptr(ci: *const fido_cbor_info_t) -> *mut *mut c_char;
    fn fido_cbor_info_extensions_len(ci: *const fido_cbor_info_t) -> usize;
    fn fido_cbor_info_maxlargeblob(ci: *const fido_cbor_info_t) -> u64;
    fn fido_cbor_info_rk_remaining(ci: *const fido_cbor_info_t) -> i64;
    fn fido_cbor_info_aaguid_ptr(ci: *const fido_cbor_info_t) -> *const u8;
    fn fido_cbor_info_aaguid_len(ci: *const fido_cbor_info_t) -> usize;
    fn fido_cbor_info_fwversion(ci: *const fido_cbor_info_t) -> u64;

    fn fido_dev_get_touch_begin(dev: *mut fido_dev_t) -> c_int;
    fn fido_dev_get_touch_status(dev: *mut fido_dev_t, touched: *mut c_int, ms: c_int) -> c_int;
    fn fido_dev_cancel(dev: *mut fido_dev_t) -> c_int;

    fn fido_cred_new() -> *mut fido_cred_t;
    fn fido_cred_free(c: *mut *mut fido_cred_t);
    fn fido_cred_set_type(c: *mut fido_cred_t, cose_alg: c_int) -> c_int;
    fn fido_cred_set_clientdata(c: *mut fido_cred_t, p: *const u8, n: usize) -> c_int;
    fn fido_cred_set_rp(c: *mut fido_cred_t, id: *const c_char, name: *const c_char) -> c_int;
    fn fido_cred_set_user(c: *mut fido_cred_t, user_id: *const u8, len: usize, name: *const c_char, display_name: *const c_char, icon: *const c_char) -> c_int;
    fn fido_cred_set_rk(c: *mut fido_cred_t, rk: fido_opt_t) -> c_int;
    fn fido_cred_set_uv(c: *mut fido_cred_t, uv: fido_opt_t) -> c_int;
    fn fido_cred_set_extensions(c: *mut fido_cred_t, ext: c_int) -> c_int;
    fn fido_cred_set_prot(c: *mut fido_cred_t, prot: c_int) -> c_int;
    fn fido_dev_make_cred(dev: *mut fido_dev_t, c: *mut fido_cred_t, pin: *const c_char) -> c_int;
    fn fido_cred_id_ptr(c: *const fido_cred_t) -> *const u8;
    fn fido_cred_id_len(c: *const fido_cred_t) -> usize;
    fn fido_cred_largeblob_key_ptr(c: *const fido_cred_t) -> *const u8;
    fn fido_cred_largeblob_key_len(c: *const fido_cred_t) -> usize;

    fn fido_assert_new() -> *mut fido_assert_t;
    fn fido_assert_free(a: *mut *mut fido_assert_t);
    fn fido_assert_set_clientdata(a: *mut fido_assert_t, p: *const u8, n: usize) -> c_int;
    fn fido_assert_set_rp(a: *mut fido_assert_t, id: *const c_char) -> c_int;
    fn fido_assert_allow_cred(a: *mut fido_assert_t, id: *const u8, n: usize) -> c_int;
    fn fido_assert_set_extensions(a: *mut fido_assert_t, ext: c_int) -> c_int;
    fn fido_assert_set_hmac_salt(a: *mut fido_assert_t, p: *const u8, n: usize) -> c_int;
    fn fido_assert_set_up(a: *mut fido_assert_t, up: fido_opt_t) -> c_int;
    fn fido_assert_set_uv(a: *mut fido_assert_t, uv: fido_opt_t) -> c_int;
    fn fido_dev_get_assert(dev: *mut fido_dev_t, a: *mut fido_assert_t, pin: *const c_char) -> c_int;
    fn fido_assert_count(a: *const fido_assert_t) -> usize;
    fn fido_assert_id_ptr(a: *const fido_assert_t, i: usize) -> *const u8;
    fn fido_assert_id_len(a: *const fido_assert_t, i: usize) -> usize;
    fn fido_assert_user_name(a: *const fido_assert_t, i: usize) -> *const c_char;
    fn fido_assert_user_id_ptr(a: *const fido_assert_t, i: usize) -> *const u8;
    fn fido_assert_user_id_len(a: *const fido_assert_t, i: usize) -> usize;
    fn fido_assert_hmac_secret_ptr(a: *const fido_assert_t, i: usize) -> *const u8;
    fn fido_assert_hmac_secret_len(a: *const fido_assert_t, i: usize) -> usize;
    fn fido_assert_largeblob_key_ptr(a: *const fido_assert_t, i: usize) -> *const u8;
    fn fido_assert_largeblob_key_len(a: *const fido_assert_t, i: usize) -> usize;

    fn fido_dev_largeblob_get(dev: *mut fido_dev_t, key: *const u8, key_len: usize, buf: *mut *mut u8, len: *mut usize) -> c_int;
    fn fido_dev_largeblob_set(dev: *mut fido_dev_t, key: *const u8, key_len: usize, buf: *const u8, len: usize, pin: *const c_char) -> c_int;
    fn fido_dev_largeblob_remove(dev: *mut fido_dev_t, key: *const u8, key_len: usize, pin: *const c_char) -> c_int;
    fn fido_dev_largeblob_get_array(dev: *mut fido_dev_t, buf: *mut *mut u8, len: *mut usize) -> c_int;

    fn fido_credman_del_dev_rk(dev: *mut fido_dev_t, cred_id: *const u8, len: usize, pin: *const c_char) -> c_int;
}

/// Relying-party id under which vault credentials are stored on the key.
/// It shows up in the key's passkey (resident credential) listings.
/// Kept from the app's working name ("FIDO2 Vault"): changing it would hide
/// every existing vault, so it is part of the on-key format.
pub const RP_ID: &str = "fido2-vault.token2";
/// Display name for new vault credentials (key managers show it).
pub const RP_NAME: &str = "FidoParole";
/// Longest vault name (credential user name), in bytes. Keeps makeCredential
/// within one short APDU on the Token2 smart-card tunnel.
pub const MAX_NAME_BYTES: usize = 32;

pub type R<T> = Result<T, String>;

// ----------------------------------------------------------------- helpers --

fn cstr(p: *const c_char) -> String {
    if p.is_null() { String::new() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() }
}

fn err_text(r: c_int) -> String {
    match r {
        0x18 => "the key's largeBlob storage is full".into(),
        0x27 => "the key denied the operation".into(),
        0x28 => "the key has no room for another discoverable credential".into(),
        0x2d => "cancelled".into(),
        0x2e => "no vault was found on this key".into(),
        0x2f | 0x3a => "timed out waiting for the key — touch it when it blinks".into(),
        0x31 => "wrong PIN".into(),
        0x32 => "PIN is blocked — the key must be reset".into(),
        0x34 => "PIN temporarily blocked — unplug and reinsert the key".into(),
        0x35 => "no FIDO PIN is set on this key — set one first with a FIDO2 management tool".into(),
        0x36 => "a PIN is required for this operation".into(),
        0x3b => "touch the key to confirm (user presence required)".into(),
        0x3c => "fingerprint verification is blocked — use the PIN".into(),
        0x3f => "user verification failed".into(),
        0x2b | 0x2c => "this key does not support a required option".into(),
        0x30 => "operation not allowed by the key".into(),
        -10 => "nothing stored on the key for this vault".into(),
        _ => format!("{} (0x{:02x})", cstr(unsafe { fido_strerr(r) }), r),
    }
}

fn rc(r: c_int) -> R<()> {
    if r == FIDO_OK { Ok(()) } else { Err(err_text(r)) }
}

/// A PIN as a C string, wiped when dropped.
struct PinC(Option<CString>);

impl Drop for PinC {
    fn drop(&mut self) {
        if let Some(c) = self.0.take() {
            use zeroize::Zeroize;
            c.into_bytes_with_nul().zeroize();
        }
    }
}

impl PinC {
    fn is_none(&self) -> bool { self.0.is_none() }
}

fn pin_c(pin: Option<&str>) -> R<PinC> {
    match pin {
        Some(p) if !p.is_empty() => CString::new(p).map(|c| PinC(Some(c))).map_err(|_| "invalid PIN".into()),
        _ => Ok(PinC(None)),
    }
}

fn pin_ptr(c: &PinC) -> *const c_char {
    c.0.as_ref().map(|c| c.as_ptr()).unwrap_or(ptr::null())
}

/// Free a buffer that libfido2 allocated with malloc(). On Windows both
/// t2fido2.dll (CMake default /MD) and Rust (MSVC, non-static CRT) use the
/// shared UCRT heap, so free() here matches libfido2's malloc().
unsafe fn free_c(p: *mut u8) {
    if !p.is_null() { libc::free(p as *mut libc::c_void) }
}

/// Copy a libfido2-owned buffer (valid until the owning object is freed).
fn copy_buf(p: *const u8, n: usize) -> Vec<u8> {
    if p.is_null() || n == 0 { Vec::new() } else { unsafe { std::slice::from_raw_parts(p, n) }.to_vec() }
}

static INIT: std::sync::Once = std::sync::Once::new();

/// libfido2 debug log to a file:
/// T2_FIDO_LOG=C:\path\fido.log. FIDO_DEBUG=1 logs to stderr instead.
/// The log holds APDU hex dumps — PIN-protocol traffic is encrypted, but
/// treat the file as sensitive and delete it after debugging.
extern "C" fn log_to_file(msg: *const c_char) {
    if msg.is_null() { return; }
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    if let Some(path) = std::env::var_os("T2_FIDO_LOG") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{}", s.trim_end());
        }
    }
}

fn ensure_init() {
    INIT.call_once(|| unsafe {
        let to_file = std::env::var_os("T2_FIDO_LOG").is_some();
        fido_init(if to_file || std::env::var_os("FIDO_DEBUG").is_some() { 1 } else { 0 });
        if to_file { fido_set_log_handler(Some(log_to_file)); }
    });
}

/// An open device; closed and freed on drop.
struct Dev(*mut fido_dev_t);

impl Dev {
    fn open(path: &str) -> R<Dev> {
        ensure_init();
        let d = unsafe { fido_dev_new() };
        if d.is_null() { return Err("out of memory".into()); }
        let c = CString::new(path).map_err(|_| "bad device path")?;
        let r = unsafe { fido_dev_open(d, c.as_ptr()) };
        if r != FIDO_OK {
            let mut d = d;
            unsafe { fido_dev_free(&mut d) };
            let mut e = err_text(r);
            if cfg!(windows) && !crate::platform::is_elevated() {
                e.push_str(". Windows only opens FIDO keys over raw USB HID for an elevated process — \
                             run FidoParole as administrator.");
            }
            return Err(e);
        }
        Ok(Dev(d))
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        unsafe {
            fido_dev_close(self.0);
            fido_dev_free(&mut self.0);
        }
    }
}

fn is_pcsc(path: &str) -> bool {
    path.starts_with("pcsc://") || path.starts_with("nfc:")
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b[..]);
    b
}

// --------------------------------------------------------------- devices ----

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceEntry {
    pub path: String,
    pub label: String,
    pub product: String,
    pub manufacturer: String,
    pub vendor_id: u16,
    pub product_id: u16,
    /// False when this process cannot open the device (Windows HID without admin).
    pub usable: bool,
    pub note: String,
    /// USB serial-number string, when the key has one and the OS exposes it.
    pub serial: String,
    /// From getInfo (empty / None when the key couldn't be asked).
    pub aaguid: String,
    pub fw_version: String,
    pub fingerprint: Option<bool>,
}

/// FIDO HID devices only. Smart-card / NFC (PC/SC) entries are skipped: the
/// Token2 CCID tunnel does not forward makeCredential / getAssertion.
pub fn list_devices() -> R<Vec<DeviceEntry>> {
    ensure_init();
    const CAP: usize = 64;
    let list = unsafe { fido_dev_info_new(CAP) };
    if list.is_null() { return Err("out of memory".into()); }
    let mut n = 0usize;
    let r = unsafe { fido_dev_info_manifest(list, CAP, &mut n) };
    let usable = !cfg!(windows) || crate::platform::is_elevated();
    let mut out = Vec::new();
    for i in 0..n {
        let di = unsafe { fido_dev_info_ptr(list, i) };
        let path = cstr(unsafe { fido_dev_info_path(di) });
        if path.starts_with("windows://") || is_pcsc(&path) { continue; }
        let manufacturer = cstr(unsafe { fido_dev_info_manufacturer_string(di) });
        let product = cstr(unsafe { fido_dev_info_product_string(di) });
        let vendor_id = unsafe { fido_dev_info_vendor(di) } as u16;
        let product_id = unsafe { fido_dev_info_product(di) } as u16;
        let label = if !product.is_empty() { product.clone() } else if !manufacturer.is_empty() { manufacturer.clone() } else { path.clone() };
        let note = if usable { "USB HID".to_string() } else { "Needs “Run as administrator”".to_string() };
        let serial = crate::platform::usb_serial(&path).unwrap_or_default();
        out.push(DeviceEntry {
            path, label, product, manufacturer, vendor_id, product_id, usable, note, serial,
            aaguid: String::new(), fw_version: String::new(), fingerprint: None,
        });
    }
    let mut l = list;
    unsafe { fido_dev_info_free(&mut l, CAP) };
    if out.is_empty() && r != FIDO_OK {
        return Err(err_text(r));
    }
    // getInfo needs no PIN or touch; it tells e.g. a Bio key (fingerprint)
    // from a PIN-only one of the same product name.
    for d in out.iter_mut().filter(|d| d.usable) {
        if let Ok(i) = key_info(&d.path) {
            d.aaguid = i.aaguid;
            d.fw_version = i.fw_version;
            d.fingerprint = Some(i.has_uv);
        }
    }
    Ok(out)
}

/// Make every listed key blink and wait for one to be touched; returns its
/// path. Used to pick between keys that look the same.
pub fn select_by_touch(paths: &[String], timeout_ms: u64) -> R<String> {
    let mut devs: Vec<(String, Dev)> = Vec::new();
    for p in paths {
        if let Ok(d) = Dev::open(p) {
            if unsafe { fido_dev_get_touch_begin(d.0) } == FIDO_OK { devs.push((p.clone(), d)); }
        }
    }
    if devs.is_empty() { return Err("none of the keys could be asked for a touch".into()); }
    let start = std::time::Instant::now();
    let mut found: Option<String> = None;
    'outer: while start.elapsed().as_millis() < timeout_ms as u128 {
        let mut i = 0;
        while i < devs.len() {
            let mut touched: c_int = 0;
            let r = unsafe { fido_dev_get_touch_status(devs[i].1 .0, &mut touched, 50) };
            if r != FIDO_OK {
                // Unplugged or refused: drop it from the race.
                devs.swap_remove(i);
                if devs.is_empty() { break 'outer; }
                continue;
            }
            if touched != 0 { found = Some(devs[i].0.clone()); break 'outer; }
            i += 1;
        }
    }
    for (p, d) in &devs {
        if found.as_deref() != Some(p.as_str()) { unsafe { fido_dev_cancel(d.0) }; }
    }
    found.ok_or_else(|| "no key was touched".to_string())
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub hmac_secret: bool,
    pub large_blob: bool,
    pub max_large_blob: u64,
    pub has_pin: bool,
    pub has_uv: bool,
    pub pin_retries: i32,
    pub rk_remaining: i64,
    pub aaguid: String,
    pub fw_version: String,
}

pub fn key_info(path: &str) -> R<KeyInfo> {
    let dev = Dev::open(path)?;
    let mut info = KeyInfo { pin_retries: -1, rk_remaining: -1, ..Default::default() };
    unsafe {
        if !fido_dev_is_fido2(dev.0) {
            return Err("this is a U2F-only device; a FIDO2 key is required".into());
        }
        info.has_pin = fido_dev_has_pin(dev.0);
        info.has_uv = fido_dev_has_uv(dev.0);
        let mut n: c_int = -1;
        if fido_dev_get_retry_count(dev.0, &mut n) == FIDO_OK { info.pin_retries = n; }
        let ci = fido_cbor_info_new();
        if ci.is_null() { return Err("out of memory".into()); }
        let r = fido_dev_get_cbor_info(dev.0, ci);
        if r == FIDO_OK {
            let p = fido_cbor_info_extensions_ptr(ci);
            let exts: Vec<String> = (0..fido_cbor_info_extensions_len(ci)).map(|i| cstr(*p.add(i))).collect();
            info.hmac_secret = exts.iter().any(|e| e == "hmac-secret");
            info.max_large_blob = fido_cbor_info_maxlargeblob(ci);
            info.large_blob = exts.iter().any(|e| e == "largeBlobKey") && info.max_large_blob > 0;
            info.rk_remaining = fido_cbor_info_rk_remaining(ci);
            let fw = fido_cbor_info_fwversion(ci);
            if fw != 0 { info.fw_version = format!("0x{fw:x}"); }
            let ag = copy_buf(fido_cbor_info_aaguid_ptr(ci), fido_cbor_info_aaguid_len(ci));
            if ag.len() == 16 {
                let h = hex::encode(ag);
                info.aaguid = format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]);
            }
        }
        let mut c = ci;
        fido_cbor_info_free(&mut c);
        rc(r)?;
    }
    Ok(info)
}

// ----------------------------------------------------------- credentials ----

pub struct NewCredential {
    pub cred_id: Vec<u8>,
}

/// Create the discoverable vault credential (one touch).
/// credProtect=3 keeps it invisible without user verification; hmac-secret
/// gives the encryption secret; largeBlobKey gives the storage slot.
pub fn create_credential(path: &str, pin: Option<&str>, vault_name: &str) -> R<NewCredential> {
    let info = key_info(path)?;
    if !info.hmac_secret { return Err("this key does not support hmac-secret".into()); }
    if !info.large_blob { return Err("this key does not support largeBlob storage".into()); }
    // hmac-secret yields a different secret with and without user verification.
    // Requiring a PIN up front guarantees we always use the UV variant, so the
    // vault can't become unreadable when a PIN is added later.
    if !info.has_pin { return Err("set a FIDO PIN on this key before creating a vault".into()); }

    let dev = Dev::open(path)?;
    let p = pin_c(pin)?;
    let rp_id = CString::new(RP_ID).unwrap();
    let rp_name = CString::new(RP_NAME).unwrap();
    if vault_name.len() > MAX_NAME_BYTES {
        return Err(format!("use a vault name of at most {MAX_NAME_BYTES} bytes"));
    }
    let user = CString::new(vault_name).map_err(|_| "invalid vault name")?;
    let user_id = crate::vault::user_handle(vault_name);
    let cdata: [u8; 32] = random_bytes();
    unsafe {
        let c = fido_cred_new();
        if c.is_null() { return Err("out of memory".into()); }
        let mut cc = c;
        let res = (|| -> R<NewCredential> {
            rc(fido_cred_set_type(c, COSE_ES256))?;
            rc(fido_cred_set_clientdata(c, cdata.as_ptr(), cdata.len()))?;
            rc(fido_cred_set_rp(c, rp_id.as_ptr(), rp_name.as_ptr()))?;
            // displayName omitted: it would repeat the name and cost request bytes.
            rc(fido_cred_set_user(c, user_id.as_ptr(), user_id.len(), user.as_ptr(), ptr::null(), ptr::null()))?;
            rc(fido_cred_set_rk(c, FIDO_OPT_TRUE))?;
            rc(fido_cred_set_extensions(c, FIDO_EXT_HMAC_SECRET | FIDO_EXT_LARGEBLOB_KEY | FIDO_EXT_CRED_PROTECT))?;
            rc(fido_cred_set_prot(c, FIDO_CRED_PROT_UV_REQUIRED))?;
            if p.is_none() { rc(fido_cred_set_uv(c, FIDO_OPT_TRUE))?; }
            rc(fido_dev_make_cred(dev.0, c, pin_ptr(&p)))?;
            let cred_id = copy_buf(fido_cred_id_ptr(c), fido_cred_id_len(c));
            // The key must hand out a largeBlob key for the credential, or there is
            // nowhere to store the vault. (The assertion returns it again.)
            if fido_cred_largeblob_key_len(c) != 32 || fido_cred_largeblob_key_ptr(c).is_null() {
                return Err("the key did not return a largeBlob key for the new credential".into());
            }
            Ok(NewCredential { cred_id })
        })();
        fido_cred_free(&mut cc);
        res
    }
}

/// A vault credential after a successful assertion: everything needed to read,
/// decrypt and write the vault. Secrets are wiped on drop.
pub struct VaultCredential {
    pub cred_id: Vec<u8>,
    pub name: String,
    pub hmac_secret: Zeroizing<[u8; 32]>,
    pub large_blob_key: Zeroizing<Vec<u8>>,
}

/// Get an assertion (one touch, with PIN or built-in UV) and return the
/// hmac-secret output for `salt` plus the largeBlob key of each vault
/// credential. `allow` restricts it to one known credential id.
pub fn assert_vault(path: &str, pin: Option<&str>, salt: &[u8; 32], allow: Option<&[u8]>) -> R<Vec<VaultCredential>> {
    let dev = Dev::open(path)?;
    let p = pin_c(pin)?;
    let rp_id = CString::new(RP_ID).unwrap();
    let cdata: [u8; 32] = random_bytes();
    unsafe {
        let a = fido_assert_new();
        if a.is_null() { return Err("out of memory".into()); }
        let mut aa = a;
        let res = (|| -> R<Vec<VaultCredential>> {
            rc(fido_assert_set_clientdata(a, cdata.as_ptr(), cdata.len()))?;
            rc(fido_assert_set_rp(a, rp_id.as_ptr()))?;
            if let Some(id) = allow { rc(fido_assert_allow_cred(a, id.as_ptr(), id.len()))?; }
            rc(fido_assert_set_extensions(a, FIDO_EXT_HMAC_SECRET | FIDO_EXT_LARGEBLOB_KEY))?;
            rc(fido_assert_set_hmac_salt(a, salt.as_ptr(), salt.len()))?;
            // User presence is the CTAP default; leaving the option out keeps
            // the request under one short APDU on the Token2 tunnel.
            rc(fido_assert_set_up(a, FIDO_OPT_OMIT))?;
            // With a PIN, libfido2 obtains a PIN/UV token (UV implied). Without
            // one, ask for built-in UV (fingerprint).
            rc(fido_assert_set_uv(a, if p.is_none() { FIDO_OPT_TRUE } else { FIDO_OPT_OMIT }))?;
            rc(fido_dev_get_assert(dev.0, a, pin_ptr(&p)))?;
            let mut out = Vec::new();
            for i in 0..fido_assert_count(a) {
                let hs = Zeroizing::new(copy_buf(fido_assert_hmac_secret_ptr(a, i), fido_assert_hmac_secret_len(a, i)));
                let lbk = Zeroizing::new(copy_buf(fido_assert_largeblob_key_ptr(a, i), fido_assert_largeblob_key_len(a, i)));
                if hs.len() != 32 || lbk.len() != 32 { continue; }
                let mut hmac = Zeroizing::new([0u8; 32]);
                hmac.copy_from_slice(&hs);
                let uid = copy_buf(fido_assert_user_id_ptr(a, i), fido_assert_user_id_len(a, i));
                let mut name = cstr(fido_assert_user_name(a, i));
                if name.is_empty() {
                    name = crate::vault::name_from_user_handle(&uid).unwrap_or_default();
                }
                out.push(VaultCredential {
                    cred_id: copy_buf(fido_assert_id_ptr(a, i), fido_assert_id_len(a, i)),
                    name,
                    hmac_secret: hmac,
                    large_blob_key: lbk,
                });
            }
            if out.is_empty() {
                return Err("the key answered but returned no hmac-secret / largeBlob key".into());
            }
            Ok(out)
        })();
        fido_assert_free(&mut aa);
        res
    }
}

// ------------------------------------------------------------- largeBlob ----

/// Read this credential's largeBlob entry. Ok(None) when nothing is stored yet.
pub fn blob_read(path: &str, large_blob_key: &[u8]) -> R<Option<Vec<u8>>> {
    let dev = Dev::open(path)?;
    let mut buf: *mut u8 = ptr::null_mut();
    let mut len = 0usize;
    let r = unsafe { fido_dev_largeblob_get(dev.0, large_blob_key.as_ptr(), large_blob_key.len(), &mut buf, &mut len) };
    if r == -10 { return Ok(None); } // FIDO_ERR_NOTFOUND
    rc(r)?;
    let v = copy_buf(buf, len);
    unsafe { free_c(buf) };
    Ok(Some(v))
}

/// Write (replace) this credential's largeBlob entry. Needs the PIN (or UV).
pub fn blob_write(path: &str, large_blob_key: &[u8], data: &[u8], pin: Option<&str>) -> R<()> {
    let dev = Dev::open(path)?;
    let p = pin_c(pin)?;
    rc(unsafe { fido_dev_largeblob_set(dev.0, large_blob_key.as_ptr(), large_blob_key.len(), data.as_ptr(), data.len(), pin_ptr(&p)) })
}

/// Size of the key's whole serialized largeBlob array (all credentials).
pub fn blob_array_size(path: &str) -> R<usize> {
    let dev = Dev::open(path)?;
    let mut buf: *mut u8 = ptr::null_mut();
    let mut len = 0usize;
    rc(unsafe { fido_dev_largeblob_get_array(dev.0, &mut buf, &mut len) })?;
    unsafe { free_c(buf) };
    Ok(len)
}

/// Remove the vault from the key: its largeBlob entry, then the credential.
pub fn delete_vault(path: &str, cred_id: &[u8], large_blob_key: &[u8], pin: Option<&str>) -> R<()> {
    let dev = Dev::open(path)?;
    let p = pin_c(pin)?;
    let r = unsafe { fido_dev_largeblob_remove(dev.0, large_blob_key.as_ptr(), large_blob_key.len(), pin_ptr(&p)) };
    if r != FIDO_OK && r != -10 { rc(r)?; }
    rc(unsafe { fido_credman_del_dev_rk(dev.0, cred_id.as_ptr(), cred_id.len(), pin_ptr(&p)) })
}
