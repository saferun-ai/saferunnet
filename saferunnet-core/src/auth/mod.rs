use serde::{Deserialize, Serialize};

/// Service node authentication token.
/// Lokinet C++ equivalent: llarp/auth/auth.hpp AuthToken
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthToken {
    pub token: Vec<u8>,
    pub expires_at: u64,
}

impl AuthToken {
    pub fn new(token: Vec<u8>, expires_at: u64) -> Self { Self { token, expires_at } }
    pub fn is_expired(&self, now: u64) -> bool { now >= self.expires_at }
}

/// Auth policy for service nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthPolicy {
    AllowAll,
    RequireToken,
    Whitelist(Vec<Vec<u8>>),
}

/// Authentication challenge sent to a connecting peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    pub nonce: Vec<u8>,
    pub expires_at: u64,
    pub challenger: Option<[u8; 32]>,
}

impl AuthChallenge {
    pub fn new(nonce: Vec<u8>, lifetime_secs: u64) -> Self {
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() + lifetime_secs;
        Self { nonce, expires_at, challenger: None }
    }
    pub fn is_expired(&self, now: u64) -> bool { now >= self.expires_at }
}

/// Auth response signed by the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Per-session auth state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAuthState {
    Unauthenticated,
    ChallengeSent(AuthChallenge),
    Authenticated,
    Failed(String),
}

impl SessionAuthState {
    pub fn is_authenticated(&self) -> bool { matches!(self, SessionAuthState::Authenticated) }
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

    #[test]
    fn test_auth_challenge_expired() {
        let mut challenge = AuthChallenge::new(vec![0u8; 32], 60);
        challenge.expires_at = 100;
        assert!(challenge.is_expired(200));
        assert!(!challenge.is_expired(50));
    }

    #[test]
    fn test_session_auth_state() {
        assert!(!SessionAuthState::Unauthenticated.is_authenticated());
        assert!(SessionAuthState::Authenticated.is_authenticated());
        assert!(!SessionAuthState::Failed("bad sig".into()).is_authenticated());
    }

    #[test]
    fn test_auth_response() {
        let resp = AuthResponse { nonce: vec![1,2,3], signature: vec![4,5,6] };
        assert_eq!(resp.nonce.len(), 3);
        assert_eq!(resp.signature.len(), 3);
    }

    #[test]
    fn test_auth_policy_variants() {
        assert!(matches!(AuthPolicy::AllowAll, AuthPolicy::AllowAll));
        assert!(matches!(AuthPolicy::RequireToken, AuthPolicy::RequireToken));
    }
}
