//! Process privilege detection and hardening.

/// Windows: true when the process token is elevated.
/// Linux/macOS: HID FIDO works for the logged-in user, so this is always true.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elev.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    true
}

/// Best effort: keep the process out of core dumps (Linux/macOS), so the
/// decrypted vault can't end up on disk through a crash dump.
pub fn harden_process() {
    #[cfg(unix)]
    unsafe {
        let rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &rl);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// USB serial-number string of a HID device, if the key reports one.
/// Many FIDO keys don't; CTAP itself has no serial number (by design).
#[cfg(target_os = "linux")]
pub fn usb_serial(path: &str) -> Option<String> {
    // /dev/hidrawN -> /sys/class/hidraw/hidrawN/device/uevent: HID_UNIQ=<serial>
    let name = std::path::Path::new(path).file_name()?.to_str()?;
    let ev = std::fs::read_to_string(format!("/sys/class/hidraw/{name}/device/uevent")).ok()?;
    let v = ev.lines().find_map(|l| l.strip_prefix("HID_UNIQ="))?.trim().to_string();
    if !v.is_empty() { return Some(v); }
    // Fall back to the USB device's own "serial" attribute.
    let mut dir = std::fs::canonicalize(format!("/sys/class/hidraw/{name}/device")).ok()?;
    for _ in 0..4 {
        if let Ok(s) = std::fs::read_to_string(dir.join("serial")) {
            let s = s.trim().to_string();
            if !s.is_empty() { return Some(s); }
        }
        if !dir.pop() { break; }
    }
    None
}

#[cfg(windows)]
pub fn usb_serial(path: &str) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Devices::HumanInterfaceDevice::HidD_GetSerialNumberString;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
    let w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        // Access 0: attributes only, no read/write of the device.
        let h = CreateFileW(PCWSTR(w.as_ptr()), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES(0), None).ok()?;
        let mut buf = [0u16; 128];
        let ok = HidD_GetSerialNumberString(h, buf.as_mut_ptr() as *mut _, (buf.len() * 2) as u32);
        let _ = CloseHandle(h);
        if !ok { return None; }
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let s = String::from_utf16_lossy(&buf[..n]).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn usb_serial(_path: &str) -> Option<String> {
    None
}
