//! FidoParole — a password vault that lives on a FIDO2 security key.
//!
//! * The vault is encrypted with a key derived from the authenticator's
//!   hmac-secret output and stored in the key's largeBlob storage.
//! * Decryption happens in memory only; nothing in plaintext is written to disk.
//! * Keys are reached over FIDO HID with libfido2. Windows only allows raw
//!   FIDO HID for an elevated process, so there the app must run as
//!   administrator (it warns and offers a restart otherwise).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod fido;
mod keyops;
mod platform;
mod vault;

use commands::*;
use std::sync::Mutex;

fn main() {
    platform::harden_process();
    let state = AppState(Mutex::new(Inner::default()));
    #[cfg(debug_assertions)]
    if std::env::var_os("FIDOPAROLE_DEMO").is_some() {
        demo_session(&state);
    }
    tauri::Builder::default()
        .manage(state)
        .manage(Clip(Mutex::new(None)))
        .setup(|app| {
            load_settings(app.handle());
            start_idle_watch(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            env_info,
            restart_as_admin,
            list_devices,
            select_by_touch,
            key_info,
            unlock,
            choose_vault,
            cancel_choose,
            create_vault,
            vault_view,
            get_entry,
            reveal_password,
            new_entry,
            update_entry,
            delete_entry,
            generate_password,
            copy_field,
            save_to_key,
            reconnect,
            lock,
            activity,
            set_lock_minutes,
            export_backup,
            pick_backup_file,
            import_backup,
            copy_to_key,
            finish_copy,
            delete_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running FidoParole");
}
