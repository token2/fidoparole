# FidoParole

**Your passwords, stored on your FIDO2 security key.**

FidoParole is a small desktop password manager for Windows, Linux and macOS.
There is no vault file on the computer and no cloud: the encrypted vault lives in
the security key's own memory, and only that key (with its PIN or fingerprint)
can decrypt it.

*Parole* is the old word for a watchword or password, in French and in English.

---

## Contents

- [What it does](#what-it-does)
- [What you need](#what-you-need)
- [Getting started](#getting-started)
- [Everyday use](#everyday-use)
- [Backups and moving to another key](#backups-and-moving-to-another-key)
- [Several keys at once](#several-keys-at-once)
- [Security model](#security-model)
- [How it works (technical)](#how-it-works-technical)
- [Troubleshooting](#troubleshooting)
- [Building from source](#building-from-source)
- [Project layout](#project-layout)
- [Limits](#limits)

---

## What it does

- **Encrypts with the key itself.** The vault key is derived (HKDF-SHA256) from the
  authenticator's **hmac-secret** output and used with AES-256-GCM. The secret never
  leaves the security key without your PIN (or fingerprint) and a touch.
- **Stores on the key.** The encrypted vault goes into the key's **largeBlob**
  storage, next to a discoverable "vault" credential. Unplug the key and the vault
  goes with it.
- **Decrypts in memory only.** Nothing in plain text is written to disk. Secrets are
  wiped from memory on lock, the vault locks itself when idle, and copied passwords
  are cleared from the clipboard after 20 seconds.
- **Backs up and moves.** Copy the vault to a second FIDO2 key (re-encrypted with that
  key's own secret), or export a passphrase-protected backup file and import or
  merge it later.
- **Simple manager.** Entries with title, username, password, URL and notes; search;
  a password generator; copy username / password / URL with one click.

## What you need

**A FIDO2 security key** that supports:

| Feature | Why |
|---------|-----|
| `hmac-secret` extension | Produces the encryption secret. |
| `largeBlobKey` extension + `largeBlobs` | Storage for the encrypted vault. |
| A **FIDO2 PIN** (set beforehand) | hmac-secret gives a different secret with and without user verification; FidoParole always uses the verified one, so a vault can't be lost by setting a PIN later. |

The app checks this for you: each key in the list shows ✓ / ✕ for these features.
Set the PIN with any FIDO2 management tool (for example Token2's Key Manager or
fido2-manage). Most current Token2 keys qualify.

**Your computer:**

| Platform | Notes |
|----------|-------|
| **Windows 10 / 11** | **Run as administrator.** Windows only lets elevated programs talk to FIDO2 keys directly over USB. Without it, the app shows a yellow warning with a *Restart as administrator* button, and keys appear greyed out. Tip: in `fidoparole.exe` → Properties → Compatibility, tick *Run this program as an administrator*. |
| **Linux** | The usual FIDO udev rules so your user can open the key (`70-u2f.rules` from libfido2 or your distribution's `libfido2` / `u2f-udev` package). |
| **macOS** | Works without extra setup. |

Only USB keys are supported. NFC and smart-card readers are not used.

## Getting started

1. **Start FidoParole** (on Windows: as administrator) and insert your key.
2. **Pick the key** in the list on the left. The panel shows its features, PIN retries
   and capacity.
3. **Create a vault:** open *Create a new vault on this key*, give it a name (up to 32
   bytes, for example `Personal`), enter the key's PIN above and press *Create vault*.
   The key **blinks twice -  touch it each time**:
   - touch 1 creates the vault credential,
   - touch 2 unlocks the key's hmac-secret, which encrypts the vault.

   The app's touch card tells you which step it is on.
4. Add entries, then press **Save to key**. Until you save, changes exist only in
   memory, and a yellow bar says so.

Next time: pick the key, enter the PIN (or tick *Use fingerprint instead of PIN* on a
fingerprint key), press **Unlock**, touch the key once. If the key holds more than one
vault, you choose which to open.

## Everyday use

| Action | How |
|--------|-----|
| Find an entry | Type in the search box (title, username, URL). |
| Copy | Click the copy button next to username, password or URL. The clipboard is cleared after 20 s, and the copy is kept out of clipboard history and cloud sync where the OS supports it. |
| Show a password | The *Show / hide* button. Passwords are only sent to the window when you ask. |
| Generate a password | *Generate* next to the password field; choose length and character sets. |
| Save | **Save to key** (header or Vault menu). No touch needed. |
| Lock | **Lock**, or wait for the auto-lock. |
| Auto-lock time | Gear icon → *Auto-lock* (1 min – 1 h). With unsaved changes it waits four times as long, then locks and **discards** them. |
| Reconnect | Vault → **Reconnect to key…** after you unplugged the key or the computer slept. Pick the key (or *Touch to pick*) and touch it once. If saving fails, the app offers this itself and saves again afterwards. |
| Delete the vault | Vault → **Delete vault from key…**. The dialog shows what will be lost, offers *Export a backup first*, and only proceeds after you tick the acknowledgement and type the vault name. Deletion is immediate and permanent. |

**Storage meter.** The bar in the header shows how much of the key's largeBlob
storage is used (by all vaults on the key). The vault is compressed before
encryption; about 40 typical entries take 2–3 KB. Most keys offer a few KB, so keep
notes short.

## Backups and moving to another key

You should always have **at least one of these**: if the key is lost, broken or reset,
the vault on it is gone.

### Copy the vault to a second key

Backup → **Copy vault to another FIDO2 key…**

1. Insert the target key (you may unplug the current one -  the vault stays open in
   memory).
2. Pick it in the list. The key the vault is on is marked *This vault's key* and
   can't be chosen. Two keys look alike? Use **Touch to pick**.
3. Enter the **target key's PIN** and press **Copy to key**.
4. The **target key blinks twice -  touch it each time.** Then the vault is written;
   don't unplug it until the dialog closes.
5. Choose whether to keep working with the current key or switch to the new one.

The copy is encrypted with the target key's own hmac-secret, so either key opens its
copy on its own. The copies are **independent**: later changes are saved only to the
key you have open. To bring the other key up to date, copy again or use a backup file
with *Merge*.

### Backup file

- **Export:** Backup → *Export encrypted backup file…*, choose a passphrase (at least
  10 characters). The `.t2vault` file is encrypted with Argon2id (64 MiB, 3 passes) +
  AES-256-GCM. It opens **without any security key**, so keep the file and the
  passphrase apart.
- **Import:** Backup → *Import backup file…* into an open vault, either **Merge** (the
  newest version of each entry wins) or **Replace**. Then *Save to key*.

To restore onto a new key: create an empty vault on it, import the backup, save.

## Several keys at once

A FIDO2 key does not give out a serial number without its PIN (that is deliberate, for
privacy), so FidoParole shows what it can read freely to tell keys apart:

- **Fingerprint** or **PIN only**,
- the **USB serial number**, if the key has one and the OS exposes it (Linux, Windows),
- **firmware version** and **AAGUID** (the AAGUID identifies the model, not the
  individual key),
- on Linux, the `hidraw` device name.

Hover a key for all details. If two keys still look the same, **Touch to pick** makes
every listed key blink and selects the one you touch. It is available in the key
list, the copy dialog and the reconnect dialog.

### Screenshots 

<img width="1040" height="700" alt="image" src="https://github.com/user-attachments/assets/d5306a15-c47e-4479-a45f-2653d00f659b" />

<img width="1040" height="700" alt="image" src="https://github.com/user-attachments/assets/320a1835-661a-4a7b-ac10-eff7e39bb644" />

<img width="1040" height="700" alt="image" src="https://github.com/user-attachments/assets/5a4ac42f-d6dc-47e6-b7fc-0ae70cbb7687" />

<img width="1040" height="700" alt="image" src="https://github.com/user-attachments/assets/d46a70dd-5ecf-4493-a997-61621ccd1468" />

## Security model

**Protected against**

- *Theft of the computer or its disk:* there is no vault on it.
- *Theft of the key alone:* the vault needs the key's PIN (8 wrong tries block the key)
  or its fingerprint, and a touch.
- *Theft of a backup file alone:* it needs the passphrase; Argon2id makes guessing
  slow.
- *Malware reading files:* nothing in plain text is written to disk.

**Not protected against**

- Malware already running on your computer while the vault is open. It could read the
  screen, the clipboard or process memory, or capture the PIN as you type it. No
  password manager can fully defend against that.
- Losing the key **and** every copy and backup. Keep a backup.

**Inside the app**

- The decrypted vault stays in the Rust process. The window receives entries
  **without passwords**; a password reaches it only when you click *show*, and copying
  happens from Rust.
- The PIN is kept in memory while unlocked (so saving doesn't ask again) and wiped on
  lock. Secrets are zeroized when dropped; core dumps are disabled on Linux and macOS.
- *Reconnect* checks the key model (AAGUID) before sending the remembered PIN, so the
  PIN never goes to a different kind of key, and then proves it is the same vault by
  getting the same hmac-secret back.
- All key operations run one at a time, so two writes can never interleave on the
  key's shared largeBlob storage.

## How it works (technical)

| Step | What happens |
|------|--------------|
| Create | `makeCredential` for RP `fido2-vault.token2`, resident key, credProtect = 3 (UV required), hmac-secret, largeBlobKey (touch 1). `getAssertion` with the fixed salt to get the hmac-secret output and the largeBlob key (touch 2). An empty vault is sealed and written with `largeBlobs`. |
| Unlock | One discoverable `getAssertion` with PIN/UV and the salt, then a `largeBlobs` read for each vault credential found. |
| Save | Fresh KDF salt and nonce, reseal, `largeBlobs` write (PIN token, no touch). |
| Copy | *Create* on the target key with the in-memory entries instead of an empty vault. |
| Reconnect | getInfo AAGUID check, then `getAssertion` allowed only for the vault's credential id; the hmac-secret must match the open vault's. If the stored blob's hash changed meanwhile, the session is marked unsaved and the user is told. |
| Delete | `largeBlobs` entry removed, then the credential (`credMgmt`). |
| Touch to pick | `fido_dev_get_touch_begin` on every key, first one touched wins, the others are cancelled. |

**hmac-secret salt:** `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ "Token2 fido2-vault v1 / hmac-secret salt")`,
the WebAuthn PRF transform of a fixed input, so a browser using the PRF extension
would reach the same secret.

**Vault name:** stored in the credential's user handle (`0x01 ‖ 8 random bytes ‖ UTF-8 name`).

**On-key format:** `"T2VLT" | v1 | kdf_salt[16] | nonce[12] | AES-256-GCM(deflate(JSON))`.
The header is the AAD; key = HKDF-SHA256(hmac-secret, kdf_salt, info). libfido2
adds its own largeBlob layer (AES-GCM under the per-credential largeBlobKey, raw
DEFLATE).

**Backup file (`.t2vault`):** `"T2VBK" | v1 | argon2 m,t,p | salt[16] | nonce[12] | AES-256-GCM(deflate(JSON))`.
Import refuses parameters above sane limits.

**Name history:** the app was developed as "FIDO2 Vault". The RP id
`fido2-vault.token2`, the salt and KDF labels and the `T2VLT` / `T2VBK` magic keep
that name because they are part of the on-key and backup formats. Changing them would
make existing vaults unreadable. In key-management tools, vault credentials appear
under `fido2-vault.token2`.

**Settings:** only the auto-lock time, in `settings.json` in the app's config folder
(`com.token2.fidoparole`). Nothing secret.

## Troubleshooting

| Symptom | What to do |
|---------|------------|
| Yellow "not running as administrator" banner, keys greyed out (Windows) | Press *Restart as administrator*, or start the exe with right-click → *Run as administrator*. |
| No key listed (Linux) | Install the FIDO udev rules, re-plug the key. Check `ls -l /dev/hidraw*`. |
| ✕ hmac-secret / ✕ largeBlob | This key model can't hold a vault. |
| "Set a FIDO2 PIN on this key first" | Set a PIN with a FIDO2 management tool, then press refresh. |
| Nothing happens after pressing a button | Look at the key: it is probably blinking and waiting for a touch. The touch card in the app says which touch it is. |
| "wrong PIN" / "PIN temporarily blocked" | After 3 wrong PINs in a row, unplug and re-insert the key. After 8, the key is blocked and must be reset (this erases its vaults). |
| Saving fails after the computer slept | Accept the *Reconnect* offer, touch the key; the app saves again. |
| "The vault on the key has changed" | Another computer saved to this key while your vault was open. *Save to key* overwrites the key's version with yours; to keep the key's version, lock without saving and unlock again. |
| "does not fit" when saving | The key's largeBlob storage is full. Shorten notes, delete old entries, or remove other vaults on the key. |
| "This key holds no saved data for this vault" | The credential exists but its data is missing (never saved, or the key's largeBlob storage was reset). Don't save. Restore from a backup or open the vault from another key. |
| Opening a vault made with an early test build fails | Builds before the PRF-style salt used a different salt. Restore from a backup file. |

Debug log: start with `T2_FIDO_LOG=<file>` (libfido2 trace to a file; it contains
protocol hex dumps, so delete it afterwards) or `FIDO_DEBUG=1` (to stderr).

## Building from source

**Windows** (Visual Studio 2022 C++ build tools, CMake, Git, Rust with the MSVC
toolchain; vcpkg is fetched automatically):

```powershell
cd fidoparole
.\build.cmd                  # or: Set-ExecutionPolicy -Scope Process Bypass; .\build.ps1
.\build.cmd -Dev             # debug build and run
.\build.cmd -RebuildFido2    # force a fresh libfido2 build
```

Output: `dist\fidoparole\` with `fidoparole.exe`, `fido2.dll` and the cbor, libcrypto
and zlib DLLs: a portable folder, no installer. Upstream libfido2 1.15.0 (USB HID only)
is cloned and built under `deps\` on the first run and reused afterwards.

**Linux / macOS:**

```bash
cd fidoparole
./build.sh                   # libfido2 linked statically -> dist/fidoparole/fidoparole
./build.sh --dev             # debug build and run
```

Linux build needs: Rust, CMake, a C compiler, pkg-config, and the development
packages for OpenSSL, libcbor, zlib, libudev and WebKitGTK 4.1 (Tauri 2). macOS:
Xcode command-line tools and `brew install openssl@3 libcbor cmake pkg-config`.

**Without a key:** a debug build started with `FIDOPAROLE_DEMO=1` opens a throw-away
in-memory vault for UI work (saving fails by design).

**Tests:** `cargo test` in `src-tauri` (vault format, KDF, backups, generator). Set
`FIDO2_LIB_DIR` to the built libfido2 (`deps/libfido2/build/src`) and
`FIDO2_LINK_STATIC=1`, as `build.sh` does.

## Project layout

```
fidoparole/
  ui/                 index.html, style.css, app.js (vanilla JS, no bundler), fonts, logo
  src-tauri/
    src/main.rs       Tauri setup, command registration
    src/commands.rs   session state, settings, all commands (the decrypted vault lives here)
    src/keyops.rs     vault operations on a key: unlock, create, write, reconnect, delete
    src/fido.rs       libfido2 FFI: devices, getInfo, makeCredential, getAssertion
                      (hmac-secret, largeBlobKey), largeBlobs, touch-to-pick
    src/vault.rs      data model, HKDF/AES-GCM sealing, Argon2id backups, generator (+ tests)
    src/platform.rs   elevation check, USB serial lookup, core-dump opt-out
    build.rs          links libfido2 (FIDO2_LIB_DIR, FIDO2_LIB_NAME, FIDO2_LINK_STATIC)
  build.ps1 / .cmd    Windows portable build
  build.sh            Linux / macOS build
```

## Limits

- Memory hygiene is best effort. Rust buffers are zeroized, but the OS web view keeps
  its own copies of whatever is shown on screen (a revealed password, notes), and text
  inputs may leave copies behind.
- Copies on different keys don't sync. Copy again, or merge a backup.
- largeBlob storage is small (a few KB on most keys): passwords and short notes, not
  files or attachments.
- USB only, no NFC. On Windows, administrator rights are required.
- No browser autofill (this needs a browser extension): copy and paste, with automatic clipboard clearing.
