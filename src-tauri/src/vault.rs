//! Vault data model and encryption. Everything here works on memory only:
//! plaintext never touches the disk, and the buffers that hold it are wiped
//! (zeroized) when they are dropped.
//!
//! On-key blob (stored in the credential's largeBlob entry):
//!
//! ```text
//!   "T2VLT" | ver=1 | kdf_salt[16] | nonce[12] | AES-256-GCM( deflate( json ) )
//!   AAD  = the 34-byte header above
//!   key  = HKDF-SHA256(ikm = hmac-secret output, salt = kdf_salt, info = KDF_INFO)
//! ```
//!
//! The hmac-secret salt sent to the authenticator is fixed (HMAC_SALT); the
//! per-credential random secret on the key is what makes the output unique.
//! kdf_salt and nonce are fresh on every save.
//!
//! Backup file (`.t2vault`), protected by a passphrase instead of a key:
//!
//! ```text
//!   "T2VBK" | ver=1 | m_cost u32 LE | t_cost u32 LE | p_cost u32 LE | salt[16] | nonce[12]
//!   | AES-256-GCM( deflate( json ) ),  key = Argon2id(passphrase, salt), AAD = header
//! ```

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub type R<T> = Result<T, String>;

const BLOB_MAGIC: &[u8; 5] = b"T2VLT";
const BACKUP_MAGIC: &[u8; 5] = b"T2VBK";
const VERSION: u8 = 1;
// The labels below keep the app's working name: they are part of the
// vault and backup formats, and changing them would make old vaults unreadable.
const KDF_INFO: &[u8] = b"Token2 fido2-vault v1 / AES-256-GCM";
/// The vault's hmac-secret input, treated as a WebAuthn PRF input; the CTAP
/// salt sent to the key is derived from it by `hmac_salt()`.
pub const PRF_INPUT: &[u8] = b"Token2 fido2-vault v1 / hmac-secret salt";
const BLOB_HEADER_LEN: usize = 5 + 1 + 16 + 12;
const BACKUP_HEADER_LEN: usize = 5 + 1 + 12 + 16 + 12;
/// Refuse to inflate anything larger than this (the key holds a few KB; a
/// backup file a few MB at most).
const MAX_PLAINTEXT: u64 = 16 * 1024 * 1024;

/// The CTAP hmac-secret salt: the WebAuthn PRF transform of PRF_INPUT,
/// SHA-256("WebAuthn PRF" || 0x00 || PRF_INPUT), as a browser or the OS
/// WebAuthn API would compute it for the same PRF input.
pub fn hmac_salt() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"WebAuthn PRF");
    h.update([0u8]);
    h.update(PRF_INPUT);
    h.finalize().into()
}

/// User handle layout shared by both backends: 0x01 || 8 random bytes ||
/// UTF-8 vault name. Windows returns no user name in assertions, so the name
/// travels in the user handle.
pub fn user_handle(name: &str) -> Vec<u8> {
    let mut id = vec![0x01u8];
    id.extend_from_slice(&random::<8>());
    id.extend_from_slice(name.as_bytes());
    id
}

pub fn name_from_user_handle(id: &[u8]) -> Option<String> {
    if id.len() > 9 && id[0] == 0x01 {
        String::from_utf8(id[9..].to_vec()).ok().filter(|s| !s.is_empty())
    } else {
        None
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b[..]);
    b
}

// ------------------------------------------------------------------ model ---

#[derive(Serialize, Deserialize, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub created: i64,
    #[serde(default)]
    pub modified: i64,
}

impl Entry {
    pub fn new(title: &str) -> Self {
        let t = now();
        let mut e = Entry::default();
        e.id = uuid::Uuid::new_v4().to_string();
        e.title = title.into();
        e.created = t;
        e.modified = t;
        e
    }
    pub fn touch(&mut self) {
        self.modified = now();
    }
}

#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    pub version: u32,
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub modified: i64,
}

impl Default for VaultData {
    fn default() -> Self {
        VaultData { version: 1, entries: Vec::new(), modified: now() }
    }
}

impl VaultData {
    /// Merge another vault in: entries with a new id are added, entries with
    /// the same id keep whichever copy was modified last. Returns (added, updated).
    pub fn merge(&mut self, other: &VaultData) -> (usize, usize) {
        let (mut added, mut updated) = (0, 0);
        for e in &other.entries {
            match self.entries.iter_mut().find(|x| x.id == e.id) {
                Some(x) if e.modified > x.modified => { *x = e.clone(); updated += 1; }
                Some(_) => {}
                None => { self.entries.push(e.clone()); added += 1; }
            }
        }
        (added, updated)
    }

    fn to_compressed(&self) -> R<Zeroizing<Vec<u8>>> {
        let json = Zeroizing::new(serde_json::to_vec(self).map_err(|e| e.to_string())?);
        let mut enc = DeflateEncoder::new(Vec::with_capacity(json.len() + 64), Compression::best());
        enc.write_all(&json).map_err(|e| e.to_string())?;
        Ok(Zeroizing::new(enc.finish().map_err(|e| e.to_string())?))
    }

    fn from_compressed(data: &[u8]) -> R<VaultData> {
        let mut json = Zeroizing::new(Vec::with_capacity(data.len() * 4));
        DeflateDecoder::new(data)
            .take(MAX_PLAINTEXT)
            .read_to_end(&mut json)
            .map_err(|_| "vault data is corrupt (decompression failed)".to_string())?;
        serde_json::from_slice(&json).map_err(|e| format!("vault data is corrupt: {e}"))
    }
}

// ---------------------------------------------------------- AEAD helpers ----

fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> R<Vec<u8>> {
    let c = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    c.encrypt(&Nonce::from(*nonce), Payload { msg, aad }).map_err(|_| "encryption failed".to_string())
}

fn aead_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let c = Aes256Gcm::new_from_slice(key).ok()?;
    c.decrypt(&Nonce::from(*nonce), Payload { msg: ct, aad }).ok().map(Zeroizing::new)
}

fn hkdf_key(hmac_secret: &[u8; 32], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), hmac_secret)
        .expand(KDF_INFO, &mut k[..])
        .expect("32 bytes is a valid HKDF-SHA256 length");
    k
}

// -------------------------------------------------------------- key blob ----

/// Encrypt the vault for the key, using the hmac-secret output.
pub fn seal(data: &VaultData, hmac_secret: &[u8; 32]) -> R<Vec<u8>> {
    let salt: [u8; 16] = random();
    let nonce: [u8; 12] = random();
    let mut header = Vec::with_capacity(BLOB_HEADER_LEN);
    header.extend_from_slice(BLOB_MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    let key = hkdf_key(hmac_secret, &salt);
    let pt = data.to_compressed()?;
    let ct = aead_seal(&key, &nonce, &header, &pt)?;
    let mut out = header;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a vault blob read from the key.
pub fn open(blob: &[u8], hmac_secret: &[u8; 32]) -> R<VaultData> {
    if blob.len() < BLOB_HEADER_LEN + 16 || &blob[..5] != BLOB_MAGIC {
        return Err("the data on this key is not a vault".into());
    }
    if blob[5] != VERSION {
        return Err(format!("unsupported vault version {}", blob[5]));
    }
    let salt = &blob[6..22];
    let nonce: [u8; 12] = blob[22..34].try_into().unwrap();
    let key = hkdf_key(hmac_secret, salt);
    let pt = aead_open(&key, &nonce, &blob[..BLOB_HEADER_LEN], &blob[BLOB_HEADER_LEN..])
        .ok_or("could not decrypt the vault (wrong key or corrupted data)")?;
    VaultData::from_compressed(&pt)
}

// ------------------------------------------------------------ backup file ---

pub struct KdfParams { pub m_cost: u32, pub t_cost: u32, pub p_cost: u32 }

/// 64 MiB, 3 passes — a deliberate ~0.5 s per guess on a desktop.
pub const BACKUP_KDF: KdfParams = KdfParams { m_cost: 64 * 1024, t_cost: 3, p_cost: 1 };

fn argon2_key(pass: &str, salt: &[u8], p: &KdfParams) -> R<Zeroizing<[u8; 32]>> {
    // Bounds keep a crafted file from demanding absurd memory or time.
    if p.m_cost > 256 * 1024 || p.t_cost > 16 || p.p_cost > 8 {
        return Err("backup file asks for unreasonable KDF parameters".into());
    }
    let params = argon2::Params::new(p.m_cost, p.t_cost, p.p_cost, Some(32)).map_err(|e| e.to_string())?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut k = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pass.as_bytes(), salt, &mut k[..]).map_err(|e| e.to_string())?;
    Ok(k)
}

pub fn export_backup(data: &VaultData, passphrase: &str) -> R<Vec<u8>> {
    export_backup_with(data, passphrase, &BACKUP_KDF)
}

pub fn export_backup_with(data: &VaultData, passphrase: &str, p: &KdfParams) -> R<Vec<u8>> {
    if passphrase.chars().count() < 10 {
        return Err("use a backup passphrase of at least 10 characters".into());
    }
    let salt: [u8; 16] = random();
    let nonce: [u8; 12] = random();
    let mut header = Vec::with_capacity(BACKUP_HEADER_LEN);
    header.extend_from_slice(BACKUP_MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&p.m_cost.to_le_bytes());
    header.extend_from_slice(&p.t_cost.to_le_bytes());
    header.extend_from_slice(&p.p_cost.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    let key = argon2_key(passphrase, &salt, p)?;
    let pt = data.to_compressed()?;
    let ct = aead_seal(&key, &nonce, &header, &pt)?;
    let mut out = header;
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn import_backup(bytes: &[u8], passphrase: &str) -> R<VaultData> {
    if bytes.len() < BACKUP_HEADER_LEN + 16 || &bytes[..5] != BACKUP_MAGIC {
        return Err("this is not a FidoParole backup file".into());
    }
    if bytes[5] != VERSION {
        return Err(format!("unsupported backup version {}", bytes[5]));
    }
    let u = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    let p = KdfParams { m_cost: u(6), t_cost: u(10), p_cost: u(14) };
    let salt = &bytes[18..34];
    let nonce: [u8; 12] = bytes[34..46].try_into().unwrap();
    let key = argon2_key(passphrase, salt, &p)?;
    let pt = aead_open(&key, &nonce, &bytes[..BACKUP_HEADER_LEN], &bytes[BACKUP_HEADER_LEN..])
        .ok_or("wrong passphrase or damaged backup file")?;
    VaultData::from_compressed(&pt)
}

// --------------------------------------------------------------- password ---

#[derive(Deserialize)]
pub struct GenOptions { pub length: usize, pub upper: bool, pub lower: bool, pub digits: bool, pub symbols: bool }

impl Default for GenOptions {
    fn default() -> Self { GenOptions { length: 20, upper: true, lower: true, digits: true, symbols: true } }
}

/// Uniform random password; guarantees one character from each chosen class.
pub fn generate_password(o: &GenOptions) -> String {
    const U: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const L: &str = "abcdefghijkmnopqrstuvwxyz";
    const D: &str = "23456789";
    const S: &str = "!#$%&*+-=?@^_~.,:;";
    let classes: Vec<&[u8]> = [(o.upper, U), (o.lower, L), (o.digits, D), (o.symbols, S)]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, s)| s.as_bytes())
        .collect();
    let classes = if classes.is_empty() { vec![L.as_bytes()] } else { classes };
    let all: Vec<u8> = classes.iter().flat_map(|c| c.iter().copied()).collect();
    let len = o.length.clamp(classes.len().max(4), 128);
    // Rejection sampling for an unbiased index.
    let pick = |set: &[u8]| -> u8 {
        let n = set.len() as u32;
        let zone = u32::MAX - (u32::MAX % n);
        loop {
            let r: u32 = rand::random();
            if r < zone { return set[(r % n) as usize]; }
        }
    };
    loop {
        let pw: Vec<u8> = (0..len).map(|_| pick(&all)).collect();
        if classes.iter().all(|c| pw.iter().any(|b| c.contains(b))) {
            return String::from_utf8(pw).unwrap();
        }
    }
}

// ------------------------------------------------------------------ tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VaultData {
        let mut v = VaultData::default();
        let mut e = Entry::new("Mail");
        e.username = "emin".into();
        e.password = "correct horse battery staple".into();
        e.url = "https://mail.example".into();
        v.entries.push(e);
        v
    }

    #[test]
    fn blob_roundtrip_and_tamper() {
        let hs = [7u8; 32];
        let blob = seal(&sample(), &hs).unwrap();
        let back = open(&blob, &hs).unwrap();
        assert_eq!(back.entries[0].password, "correct horse battery staple");
        assert!(open(&blob, &[8u8; 32]).is_err(), "wrong hmac-secret must fail");
        let mut bad = blob.clone();
        bad[10] ^= 1; // header is authenticated
        assert!(open(&bad, &hs).is_err());
        let mut bad = blob.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(open(&bad, &hs).is_err());
        // fresh salt + nonce on each save
        assert_ne!(seal(&sample(), &hs).unwrap()[6..34], blob[6..34]);
    }

    #[test]
    fn backup_roundtrip() {
        let p = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let f = export_backup_with(&sample(), "a long passphrase", &p).unwrap();
        assert_eq!(import_backup(&f, "a long passphrase").unwrap().entries[0].title, "Mail");
        assert!(import_backup(&f, "wrong passphrase!").is_err());
        assert!(export_backup_with(&sample(), "short", &p).is_err());
    }

    #[test]
    fn merge_keeps_newest() {
        let mut a = sample();
        let mut b = a.clone();
        b.entries[0].password = "newer".into();
        b.entries[0].modified += 10;
        b.entries.push(Entry::new("Bank"));
        assert_eq!(a.merge(&b), (1, 1));
        assert_eq!(a.entries[0].password, "newer");
    }

    #[test]
    fn prf_salt_and_user_handle() {
        // SHA-256("WebAuthn PRF" || 0x00 || input), as Windows computes it.
        let mut m = b"WebAuthn PRF".to_vec();
        m.push(0);
        m.extend_from_slice(PRF_INPUT);
        let want: [u8; 32] = Sha256::digest(&m).into();
        assert_eq!(hmac_salt(), want);
        let h = user_handle("Personal");
        assert_eq!(h.len(), 9 + 8);
        assert_eq!(name_from_user_handle(&h).as_deref(), Some("Personal"));
        assert_eq!(name_from_user_handle(&[1, 2, 3]), None);
    }

    #[test]
    fn generator() {
        let o = GenOptions { length: 32, ..Default::default() };
        let p = generate_password(&o);
        assert_eq!(p.len(), 32);
        assert!(p.chars().any(|c| c.is_ascii_digit()) && p.chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn compact_on_key() {
        // ~40 typical entries should stay within a few KB after compression.
        let mut v = VaultData::default();
        for i in 0..40 {
            let mut e = Entry::new(&format!("Site {i}"));
            e.username = format!("user{i}@example.com");
            e.password = generate_password(&GenOptions::default());
            e.url = format!("https://site{i}.example.com/login");
            v.entries.push(e);
        }
        let blob = seal(&v, &[1u8; 32]).unwrap();
        eprintln!("40 entries -> {} bytes", blob.len());
        assert!(blob.len() < 4096);
    }
}
