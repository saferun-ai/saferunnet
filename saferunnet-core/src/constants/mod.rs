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
}
