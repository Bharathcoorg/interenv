/// Install the Apple Sandbox profile confining process writes and denying network outbound.
#[cfg(target_os = "macos")]
pub fn install() -> Result<(), String> {
    let profile = r#"
        (version 1)
        (deny default)
        (allow process-exec)
        (allow process-fork)
        (allow signal (target self))
        (allow sysctl-read)
        (allow file-read*)
        (allow file-write* (regex #"^/dev/null$"))
        (allow file-write* (regex #"^/dev/tty$"))
        (allow file-write* (regex #"^/private/tmp/.*"))
        (deny network-outbound (remote ip))
    "#;

    extern "C" {
        fn sandbox_init(profile: *const u8, flags: u64, error_out: *mut *mut u8) -> i32;
    }

    let profile_c = std::ffi::CString::new(profile).map_err(|e| e.to_string())?;
    let mut err_buf: *mut u8 = std::ptr::null_mut();
    // SAFETY: sandbox_init receives a valid null-terminated C-string profile
    // and a pointer to receive any error buffer allocated by libsandbox.
    let rc = unsafe { sandbox_init(profile_c.as_ptr() as *const u8, 0, &mut err_buf) };
    if rc != 0 {
        let msg = if err_buf.is_null() {
            "unknown".to_string()
        } else {
            // SAFETY: err_buf points to a valid null-terminated C string on error.
            let cstr = unsafe { std::ffi::CStr::from_ptr(err_buf as *const i8) };
            cstr.to_string_lossy().into_owned()
        };
        return Err(format!("sandbox_init failed: {}", msg));
    }
    Ok(())
}
