use serde::{Deserialize, Serialize};
// ── Auth Codes & Result Types ───────────────────────────────────────────────

/// Authentication result codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthCode {
    Accepted,
    Rejected,
    Failed,
    RateLimit,
    PaymentRequired,
}

impl AuthCode {
    pub fn to_status_string(&self) -> &'static str {
        match self {
            AuthCode::Accepted => "accepted",
            AuthCode::Rejected => "rejected",
            AuthCode::Failed => "failed",
            AuthCode::RateLimit => "rate_limit",
            AuthCode::PaymentRequired => "payment_required",
        }
    }

    pub fn to_http_code(&self) -> u16 {
        match self {
            AuthCode::Accepted => 200,
            AuthCode::Rejected => 403,
            AuthCode::Failed => 500,
            AuthCode::RateLimit => 429,
            AuthCode::PaymentRequired => 402,
        }
    }

    pub fn is_success(&self) -> bool { matches!(self, AuthCode::Accepted) }
}

/// Structured authentication result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResult {
    pub code: AuthCode,
    pub reason: Option<String>,
}

impl AuthResult {
    pub fn accepted() -> Self { Self { code: AuthCode::Accepted, reason: None } }
    pub fn rejected(reason: impl Into<String>) -> Self { Self { code: AuthCode::Rejected, reason: Some(reason.into()) } }
    pub fn failed(reason: impl Into<String>) -> Self { Self { code: AuthCode::Failed, reason: Some(reason.into()) } }
    pub fn is_accepted(&self) -> bool { self.code == AuthCode::Accepted }
}

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

    #[test]
    fn test_auth_code_to_status_string() {
        assert_eq!(AuthCode::Accepted.to_status_string(), "accepted");
        assert_eq!(AuthCode::Rejected.to_status_string(), "rejected");
        assert_eq!(AuthCode::Failed.to_status_string(), "failed");
        assert_eq!(AuthCode::RateLimit.to_status_string(), "rate_limit");
        assert_eq!(AuthCode::PaymentRequired.to_status_string(), "payment_required");
    }

    #[test]
    fn test_auth_code_to_http_code() {
        assert_eq!(AuthCode::Accepted.to_http_code(), 200);
        assert_eq!(AuthCode::Rejected.to_http_code(), 403);
        assert_eq!(AuthCode::Failed.to_http_code(), 500);
        assert_eq!(AuthCode::RateLimit.to_http_code(), 429);
        assert_eq!(AuthCode::PaymentRequired.to_http_code(), 402);
    }

    #[test]
    fn test_auth_code_is_success() {
        assert!(AuthCode::Accepted.is_success());
        assert!(!AuthCode::Rejected.is_success());
        assert!(!AuthCode::RateLimit.is_success());
    }

    #[test]
    fn test_auth_result_accepted() {
        assert!(AuthResult::accepted().is_accepted());
        assert!(!AuthResult::rejected("no").is_accepted());
        assert!(!AuthResult::failed("err").is_accepted());
    }
}