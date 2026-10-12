// Links libfido2 built by build.ps1 / build.sh (upstream, USB HID only).
// On Windows the default backend is webauthn.dll (linked through the
// `windows` crate); libfido2 is the opt-in "Direct USB HID" backend.
// The patch adds the Token2 CTAP-over-CCID tunnel, so Token2 keys enumerate as
// pcsc:// devices and work for a normal (non-elevated) user on Windows.
//
//   FIDO2_LIB_DIR     directory containing the import/static library
//   FIDO2_LIB_NAME    library name (default: "fido2")
//   FIDO2_LINK_STATIC set to link the static archive (Linux/macOS)
fn main() {
    println!("cargo:rerun-if-env-changed=FIDO2_LIB_DIR");
    println!("cargo:rerun-if-env-changed=FIDO2_LIB_NAME");
    println!("cargo:rerun-if-env-changed=FIDO2_LINK_STATIC");

    if let Ok(dir) = std::env::var("FIDO2_LIB_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
    }
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let name = std::env::var("FIDO2_LIB_NAME").unwrap_or_else(|_| {
        "fido2".into()
    });

    if std::env::var("FIDO2_LINK_STATIC").is_ok() {
        println!("cargo:rustc-link-lib=static={name}");
        for dep in ["cbor", "crypto", "z"] {
            println!("cargo:rustc-link-lib=dylib={dep}");
        }
        match target_os.as_str() {
            "linux" => {
                println!("cargo:rustc-link-lib=dylib=udev");
            }
            "macos" => {
                println!("cargo:rustc-link-lib=framework=IOKit");
                println!("cargo:rustc-link-lib=framework=CoreFoundation");
            }
            _ => {}
        }
    } else {
        println!("cargo:rustc-link-lib=dylib={name}");
    }
    tauri_build::build()
}
