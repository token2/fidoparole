//! Vault operations on a key over FIDO HID (libfido2). On Windows raw FIDO
//! HID is only available to an elevated process; the UI warns otherwise.

use crate::fido::{self, VaultCredential};
use crate::vault::{self, VaultData};

pub type R<T> = Result<T, String>;

/// Credential(s) found on a key, with their (still encrypted) blobs.
pub struct Unlocked {
    pub path: String,
    pub creds: Vec<(VaultCredential, Option<Vec<u8>>)>,
    pub used: usize,
    pub max: u64,
    /// AAGUID of the key (model identifier, not unique per key).
    pub aaguid: String,
}

/// One discoverable assertion (PIN/UV + touch), then a largeBlob read per vault.
pub fn unlock(path: &str, pin: Option<&str>) -> R<Unlocked> {
    let creds = fido::assert_vault(path, pin, &vault::hmac_salt(), None)?;
    let mut out = Vec::new();
    for c in creds {
        let blob = fido::blob_read(path, &c.large_blob_key)?;
        out.push((c, blob));
    }
    let used = fido::blob_array_size(path).unwrap_or(0);
    let info = fido::key_info(path).unwrap_or_default();
    Ok(Unlocked { path: path.into(), creds: out, used, max: info.max_large_blob, aaguid: info.aaguid })
}

/// Progress of a two-touch operation, reported before each step.
#[derive(Clone, Copy)]
pub enum Step {
    /// makeCredential: waiting for touch 1.
    CreateCredential = 1,
    /// getAssertion: waiting for touch 2.
    UnlockSecret = 2,
    /// largeBlob write: no touch, don't unplug.
    Write = 3,
}

/// Make a vault credential and store `data` in it (two touches).
pub fn create(path: &str, pin: Option<&str>, name: &str, data: &VaultData, step: &dyn Fn(Step)) -> R<Unlocked> {
    let info = fido::key_info(path)?;
    step(Step::CreateCredential);
    let nc = fido::create_credential(path, pin, name)?;
    // Discoverable assertion, then pick the new credential by id.
    step(Step::UnlockSecret);
    let mut creds = fido::assert_vault(path, pin, &vault::hmac_salt(), None)?;
    let idx = creds.iter().position(|c| c.cred_id == nc.cred_id)
        .ok_or("the new vault credential was not returned by the key")?;
    let mut cred = creds.swap_remove(idx);
    if cred.name.is_empty() { cred.name = name.to_string(); }
    let blob = vault::seal(data, &cred.hmac_secret)?;
    step(Step::Write);
    fido::blob_write(path, &cred.large_blob_key, &blob, pin)?;
    let used = fido::blob_array_size(path).unwrap_or(blob.len());
    Ok(Unlocked { path: path.into(), creds: vec![(cred, Some(blob))], used, max: info.max_large_blob, aaguid: info.aaguid })
}

/// Find the vault again on a key that was unplugged / replugged (its device
/// path may have changed). Checks the model first so the PIN is never sent to
/// a key of another kind, then one assertion restricted to the vault's
/// credential (touch). The hmac-secret must match the open vault's.
pub struct Reconnected {
    pub cred: VaultCredential,
    pub blob: Option<Vec<u8>>,
    pub used: usize,
    pub max: u64,
}

pub fn reconnect(path: &str, pin: Option<&str>, aaguid: &str, cred_id: &[u8], hmac_secret: &[u8; 32]) -> R<Reconnected> {
    let info = fido::key_info(path)?;
    if !aaguid.is_empty() && !info.aaguid.is_empty() && info.aaguid != aaguid {
        return Err("this is not the key the vault was opened from (different key model)".into());
    }
    let mut creds = fido::assert_vault(path, pin, &vault::hmac_salt(), Some(cred_id)).map_err(|e| {
        if e == "no vault was found on this key" { "this vault is not on that key".to_string() } else { e }
    })?;
    let idx = creds.iter().position(|c| c.cred_id == cred_id).ok_or("this vault is not on that key")?;
    let cred = creds.swap_remove(idx);
    // Constant-time compare of the two secrets.
    let diff = cred.hmac_secret.iter().zip(hmac_secret.iter()).fold(0u8, |a, (x, y)| a | (x ^ y));
    if diff != 0 { return Err("the key answered with a different secret for this vault".into()); }
    let blob = fido::blob_read(path, &cred.large_blob_key)?;
    let used = fido::blob_array_size(path).unwrap_or(0);
    Ok(Reconnected { cred, blob, used, max: info.max_large_blob })
}

/// Store an encrypted blob; returns the key's largeBlob usage (0 if unknown).
pub fn write(path: &str, large_blob_key: &[u8], blob: &[u8], pin: Option<&str>) -> R<usize> {
    fido::blob_write(path, large_blob_key, blob, pin)?;
    Ok(fido::blob_array_size(path).unwrap_or(0))
}

/// Remove the vault: its largeBlob entry, then the credential.
pub fn delete(path: &str, cred_id: &[u8], large_blob_key: &[u8], pin: Option<&str>) -> R<()> {
    fido::delete_vault(path, cred_id, large_blob_key, pin)
}
