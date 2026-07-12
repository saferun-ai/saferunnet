/// Protocol version for SaferunNet
pub const PROTOCOL_VERSION: u16 = 1;

/// Default port for inter-router QUIC communication
pub const DEFAULT_QUIC_PORT: u16 = 22000;

/// Default Lokinet DNS TLD
pub const LOKI_TLD: &str = ".loki";

/// Maximum path length (number of hops)
pub const MAX_PATH_LENGTH: usize = 4;

/// Default path lifetime in seconds
pub const DEFAULT_PATH_LIFETIME: u64 = 600; // 10 minutes

/// Maximum number of paths to maintain
pub const MAX_PATHS: usize = 8;

/// Default link session timeout in seconds
pub const LINK_SESSION_TIMEOUT: u64 = 30;

/// Service node ping interval in seconds
pub const PING_INTERVAL: u64 = 10;

/// Maximum time without ping before warning (seconds)
pub const MAX_TIME_WITHOUT_PING: u64 = 120;

/// Maximum backoff for reachability testing (seconds)
pub const MAX_TESTING_BACKOFF: u64 = 120;

/// Bucket size for DHT
pub const DHT_BUCKET_SIZE: usize = 20;

// ── Version Constants ──────────────────────────────────────────────────────

pub const VERSION_MAJOR: u16 = 0;
pub const VERSION_MINOR: u16 = 9;
pub const VERSION_PATCH: u16 = 0;
pub const VERSION_STR: &str = "0.9.0";

pub const fn router_version() -> [u8; 3] {
    [VERSION_MAJOR as u8, VERSION_MINOR as u8, VERSION_PATCH as u8]
}

pub fn version_string() -> String {
    format!("{}.{}.{}", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH)
}

pub fn version_bytes() -> [u8; 3] { router_version() }

pub fn is_compatible_version(remote: [u8; 3]) -> bool {
    remote[0] == VERSION_MAJOR as u8 && (remote[1] as i16 - VERSION_MINOR as i16).abs() <= 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_sanity() {
        assert!(PROTOCOL_VERSION > 0);
        assert!(MAX_PATH_LENGTH >= 2);
        assert!(MAX_PATHS > 0);
        assert!(!LOKI_TLD.is_empty());
    }

    #[test]
    fn test_version_string() { assert_eq!(version_string(), "0.9.0"); }

    #[test]
    fn test_version_bytes() { assert_eq!(version_bytes(), [0, 9, 0]); }

    #[test]
    fn test_is_compatible_same() { assert!(is_compatible_version([0, 9, 0])); }

    #[test]
    fn test_is_compatible_minor_plus_one() { assert!(is_compatible_version([0, 10, 0])); }

    #[test]
    fn test_is_compatible_minor_minus_one() { assert!(is_compatible_version([0, 8, 0])); }

    #[test]
    fn test_is_compatible_incompatible_major() { assert!(!is_compatible_version([1, 9, 0])); }

    #[test]
    fn test_is_compatible_incompatible_minor() { assert!(!is_compatible_version([0, 7, 0])); }
}