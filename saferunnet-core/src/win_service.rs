/// Windows service wrapper for running SaferunNet as a system service.
#[cfg(target_os = "windows")]
pub mod win_service {
    use std::ffi::OsString;

    /// Service name registered with Windows SCM.
    pub const SERVICE_NAME: &str = "SaferunNet";
    /// Service display name.
    pub const DISPLAY_NAME: &str = "SaferunNet VPN Daemon";

    /// Install the service into Windows SCM.
    /// Requires Administrator privileges.
    pub fn install_service(binary_path: &str) -> Result<(), String> {
        let output = std::process::Command::new("sc")
            .args([
                "create", SERVICE_NAME,
                "binPath=", binary_path,
                "start=", "auto",
                "DisplayName=", DISPLAY_NAME,
            ])
            .output()
            .map_err(|e| format!("failed to run sc: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("sc create failed: {stderr}"))
        }
    }

    /// Uninstall the service from Windows SCM.
    pub fn uninstall_service() -> Result<(), String> {
        let output = std::process::Command::new("sc")
            .args(["delete", SERVICE_NAME])
            .output()
            .map_err(|e| format!("failed to run sc: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("sc delete failed: {stderr}"))
        }
    }

    /// Check if the service is installed.
    pub fn is_installed() -> bool {
        std::process::Command::new("sc")
            .args(["query", SERVICE_NAME])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test] fn test_service_name() { assert_eq!(SERVICE_NAME, "SaferunNet"); }
        #[test] fn test_install_non_admin() { let r = install_service("saferunnet.exe"); assert!(r.is_err()); }
    }
}

/// Stub for non-Windows platforms.
#[cfg(not(target_os = "windows"))]
pub mod win_service {
    pub const SERVICE_NAME: &str = "SaferunNet";
    pub fn install_service(_path: &str) -> Result<(), String> { Err("not supported on this platform".into()) }
    pub fn uninstall_service() -> Result<(), String> { Err("not supported on this platform".into()) }
    pub fn is_installed() -> bool { false }
}
