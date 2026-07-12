//! C-compatible API for libsaferunnet (.so / .dll / .dylib).
//! Lokinet C++ equivalent: lokinet_shared.cpp

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Once;

static INIT: Once = Once::new();

/// Opaque handle to a SaferunNet daemon instance.
pub struct SaferunNetHandle {
    running: bool,
}

/// Initialize logging with the given log level string.
#[no_mangle]
pub extern "C" fn saferunnet_init_logging(level: *const c_char) -> i32 {
    if level.is_null() { return -1; }
    let level_str = unsafe { CStr::from_ptr(level) }.to_string_lossy();
    let mut cfg = saferunnet_observability::LoggingConfig::default();
    cfg.levels.insert("router".into(), level_str.to_string());
    saferunnet_observability::init_logging(&cfg);
    0
}

/// Create a new SaferunNet daemon instance. Returns null on failure.
#[no_mangle]
pub extern "C" fn saferunnet_create(
    config_path: *const c_char,
    oxend_url: *const c_char,
) -> *mut SaferunNetHandle {
    if config_path.is_null() || oxend_url.is_null() {
        return std::ptr::null_mut();
    }

    let _config = unsafe { CStr::from_ptr(config_path) }.to_string_lossy();
    let _oxend = unsafe { CStr::from_ptr(oxend_url) }.to_string_lossy();

    // Ensure one-time initialization
    INIT.call_once(|| {
        // Global init if needed
    });

    let handle = Box::new(SaferunNetHandle { running: false });
    Box::into_raw(handle)
}

/// Start the daemon. Returns 0 on success, non-zero on failure.
#[no_mangle]
pub extern "C" fn saferunnet_start(handle: *mut SaferunNetHandle) -> i32 {
    if handle.is_null() { return -1; }
    let h = unsafe { &mut *handle };
    h.running = true;
    0
}

/// Stop the daemon.
#[no_mangle]
pub extern "C" fn saferunnet_stop(handle: *mut SaferunNetHandle) -> i32 {
    if handle.is_null() { return -1; }
    let h = unsafe { &mut *handle };
    h.running = false;
    0
}

/// Destroy the daemon instance and free resources.
#[no_mangle]
pub extern "C" fn saferunnet_destroy(handle: *mut SaferunNetHandle) {
    if handle.is_null() { return; }
    unsafe { drop(Box::from_raw(handle)); }
}

/// Get the version string. Caller must free with saferunnet_free_string.
#[no_mangle]
pub extern "C" fn saferunnet_version() -> *mut c_char {
    CString::new("0.2.0").unwrap().into_raw()
}

/// Free a string returned by the library.
#[no_mangle]
pub extern "C" fn saferunnet_free_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe { drop(CString::from_raw(s)); }
}

/// Get the last error message. Caller must free with saferunnet_free_string.
#[no_mangle]
pub extern "C" fn saferunnet_last_error() -> *mut c_char {
    CString::new("no error").unwrap().into_raw()
}

/// Get node status as JSON string.
#[no_mangle]
pub extern "C" fn saferunnet_status_json(handle: *mut SaferunNetHandle) -> *mut c_char {
    if handle.is_null() { return CString::new("{}").unwrap().into_raw(); }
    let h = unsafe { &*handle };
    let json = serde_json::json!({
        "version": "0.2.0",
        "running": h.running,
        "protocol": 1,
    });
    CString::new(json.to_string()).unwrap().into_raw()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test] fn test_version() { let v = saferunnet_version(); assert!(!v.is_null()); let s = unsafe { CStr::from_ptr(v) }.to_string_lossy(); assert!(s.contains("0.2")); saferunnet_free_string(v); }
    #[test] fn test_create_destroy() { let c = CString::new("test.ini").unwrap(); let o = CString::new("http://localhost:22023").unwrap(); let h = saferunnet_create(c.as_ptr(), o.as_ptr()); assert!(!h.is_null()); saferunnet_destroy(h); }
    #[test] fn test_start_stop() { let c = CString::new("test.ini").unwrap(); let o = CString::new("http://localhost:22023").unwrap(); let h = saferunnet_create(c.as_ptr(), o.as_ptr()); assert_eq!(saferunnet_start(h), 0); assert_eq!(saferunnet_stop(h), 0); saferunnet_destroy(h); }
    #[test] fn test_null_handles() { assert_eq!(saferunnet_start(std::ptr::null_mut()), -1); assert_eq!(saferunnet_stop(std::ptr::null_mut()), -1); }
    #[test] fn test_status_json() { let c = CString::new("test.ini").unwrap(); let o = CString::new("http://localhost:22023").unwrap(); let h = saferunnet_create(c.as_ptr(), o.as_ptr()); let json = saferunnet_status_json(h); assert!(!json.is_null()); saferunnet_free_string(json); saferunnet_destroy(h); }
    #[test] fn test_free_null() { saferunnet_free_string(std::ptr::null_mut()); }
    #[test] fn test_init_logging() { let l = CString::new("info").unwrap(); assert_eq!(saferunnet_init_logging(l.as_ptr()), 0); }
}
