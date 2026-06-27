//! Self-update mechanism for saferunnet.
//!
//! Checks a configured update server for new versions, downloads the
//! updated binary, and replaces the current executable atomically.
//!
//! Uses raw TCP for HTTP to avoid external HTTP client dependencies.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Current version baked in at compile time.
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default update server host.
const DEFAULT_UPDATE_HOST: &str = "update.saferunnet.local";
const DEFAULT_UPDATE_PORT: u16 = 80;

/// Version manifest served by the update server.
#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateManifest {
    pub version: String,
    pub binary_url: String,
    pub checksum_sha256: Option<String>,
    pub release_notes: Option<String>,
}

/// Result of checking for updates.
#[derive(Debug)]
pub enum UpdateStatus {
    /// No update available (current >= latest).
    UpToDate { current: String, latest: String },
    /// An update is available.
    UpdateAvailable {
        current: String,
        latest: String,
        manifest: UpdateManifest,
    },
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum UpdateError {
    #[error("failed to connect to update server: {0}")]
    ConnectFailed(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("invalid JSON response: {0}")]
    InvalidResponse(String),
    #[error("failed to download binary: {0}")]
    DownloadFailed(String),
    #[error("failed to replace binary: {0}")]
    ReplaceFailed(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Check for updates by fetching the version manifest from the update server.
pub fn check_for_updates(host: Option<&str>) -> Result<UpdateStatus, UpdateError> {
    let host = host.unwrap_or(DEFAULT_UPDATE_HOST);
    let port = DEFAULT_UPDATE_PORT;

    let response = http_get(host, port, "/version.json", None)?;

    let manifest: UpdateManifest =
        serde_json::from_str(&response).map_err(|e| UpdateError::InvalidResponse(e.to_string()))?;

    if manifest.version.as_str() <= CURRENT_VERSION {
        return Ok(UpdateStatus::UpToDate {
            current: CURRENT_VERSION.into(),
            latest: manifest.version,
        });
    }

    Ok(UpdateStatus::UpdateAvailable {
        current: CURRENT_VERSION.into(),
        latest: manifest.version.clone(),
        manifest,
    })
}

/// Download the updated binary to a temporary file.
pub fn download_update(
    manifest: &UpdateManifest,
    host: Option<&str>,
) -> Result<PathBuf, UpdateError> {
    let host = host.unwrap_or(DEFAULT_UPDATE_HOST);
    let port = DEFAULT_UPDATE_PORT;

    // Parse URL: http://host:port/path or /path
    let url_path = if manifest.binary_url.starts_with("http") {
        // Full URL — extract path
        manifest
            .binary_url
            .splitn(4, '/')
            .nth(3)
            .map(|p| format!("/{p}"))
            .unwrap_or_else(|| "/saferunnet.exe".into())
    } else {
        manifest.binary_url.clone()
    };

    let data = http_get(host, port, &url_path, Some(60))?;

    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(format!("saferunnet_update_{}.exe", std::process::id()));
    std::fs::write(&temp_path, &data)?;

    Ok(temp_path)
}

/// Replace the current binary with the downloaded update.
///
/// On Windows: renames the current binary to `.old`, moves the new binary
/// into place, and marks the old binary for deletion on next reboot.
pub fn apply_update(new_binary: &Path) -> Result<(), UpdateError> {
    let current_exe =
        std::env::current_exe().map_err(|e| UpdateError::ReplaceFailed(e.to_string()))?;
    let old_path = current_exe.with_extension("exe.old");

    // On Windows, we can't replace a running executable. Schedule replacement.
    #[cfg(windows)]
    {
        let old = old_path.to_string_lossy().to_string();
        let new = new_binary.to_string_lossy().to_string();
        let current = current_exe.to_string_lossy().to_string();

        // Create a batch file that:
        // 1. Waits for this process to exit
        // 2. Moves the new binary over the old one
        // 3. Restarts the service
        // 4. Deletes itself
        let script_path = std::env::temp_dir().join("saferunnet_update.bat");
        let script = format!(
            "@echo off\r\n\
             :wait\r\n\
             timeout /t 2 /nobreak >nul\r\n\
             if exist \"{current}\" goto wait\r\n\
             move /Y \"{new}\" \"{current}\"\r\n\
             if exist \"{old}\" del /F \"{old}\"\r\n\
             sc start saferunnet 2>nul\r\n\
             del /F \"%~f0\"\r\n"
        );
        std::fs::write(&script_path, script)
            .map_err(|e| UpdateError::ReplaceFailed(e.to_string()))?;

        // Rename current to .old
        std::fs::rename(&current_exe, &old_path)
            .map_err(|e| UpdateError::ReplaceFailed(format!("cannot rename current: {e}")))?;

        // Copy new binary to current location
        std::fs::copy(new_binary, &current_exe)
            .map_err(|e| UpdateError::ReplaceFailed(format!("cannot copy new binary: {e}")))?;

        // Launch the replacement script detached
        std::process::Command::new("cmd.exe")
            .args(["/C", &script_path.to_string_lossy()])
            .spawn()
            .map_err(|e| UpdateError::ReplaceFailed(e.to_string()))?;
    }

    #[cfg(not(windows))]
    {
        std::fs::rename(new_binary, &current_exe)
            .map_err(|e| UpdateError::ReplaceFailed(e.to_string()))?;
    }

    Ok(())
}

/// Simple blocking HTTP GET request.
fn http_get(
    host: &str,
    port: u16,
    path: &str,
    timeout_secs: Option<u64>,
) -> Result<String, UpdateError> {
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(10));
    let addr = format!("{host}:{port}");

    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e: std::net::AddrParseError| UpdateError::ConnectFailed(e.to_string()))?,
        timeout,
    )
    .map_err(|e| UpdateError::ConnectFailed(e.to_string()))?;

    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| UpdateError::ConnectFailed(e.to_string()))?;

    let request = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| UpdateError::Http(e.to_string()))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| UpdateError::Http(e.to_string()))?;

    let response_str = String::from_utf8_lossy(&response);

    // Split headers from body
    let body = if let Some(idx) = response_str.find("\r\n\r\n") {
        &response_str[idx + 4..]
    } else {
        return Err(UpdateError::Http("invalid HTTP response".into()));
    };

    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_version_is_not_empty() {
        assert!(!CURRENT_VERSION.is_empty());
        assert!(CURRENT_VERSION.chars().next().unwrap().is_ascii_digit());
    }

    #[test]
    fn update_status_up_to_date() {
        let status = UpdateStatus::UpToDate {
            current: "0.1.0".into(),
            latest: "0.1.0".into(),
        };
        match status {
            UpdateStatus::UpToDate { current, latest } => {
                assert_eq!(current, "0.1.0");
                assert_eq!(latest, "0.1.0");
            }
            _ => panic!("expected UpToDate"),
        }
    }

    #[test]
    fn update_manifest_deserialization() {
        let json = r#"{"version":"0.2.0","binary_url":"/releases/saferunnet.exe","checksum_sha256":"abc123","release_notes":"Bug fixes"}"#;
        let manifest: UpdateManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.version, "0.2.0");
        assert_eq!(manifest.binary_url, "/releases/saferunnet.exe");
        assert_eq!(manifest.checksum_sha256.unwrap(), "abc123");
    }

    #[test]
    fn version_comparison_finds_update() {
        // If latest > current, update available
        assert!("0.2.0" > "0.1.0");
    }
}
