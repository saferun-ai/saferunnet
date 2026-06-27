use serde::{Deserialize, Serialize};

/// Service node authentication token.
/// Lokinet C++ equivalent: llarp/auth/auth.hpp AuthToken
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthToken {
    pub token: Vec<u8>,
    pub expires_at: u64,
}

impl AuthToken {
    pub fn new(token: Vec<u8>, expires_at: u64) -> Self {
        Self { token, expires_at }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// Auth policy for service nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthPolicy {
    /// Accept any connection
    AllowAll,
    /// Require valid auth token
    RequireToken,
    /// Whitelist specific public keys
    Whitelist(Vec<Vec<u8>>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_token_expiry() {
        let token = AuthToken::new(vec![1, 2, 3], 1000);
        assert!(!token.is_expired(500));
        assert!(token.is_expired(1000));
        assert!(token.is_expired(1001));
    }
}
