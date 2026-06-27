use saferunnet_crypto::PublicKey;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("not a .loki name: {0}")]
    NotLokiName(String),
    #[error("invalid loki name characters: {0}")]
    InvalidCharacters(String),
    #[error("name not found: {0}")]
    NotFound(String),
}

pub trait LokiResolver {
    fn resolve(&self, name: &str) -> Result<Vec<PublicKey>, DnsError>;
}

pub fn is_loki_name(name: &str) -> bool {
    name.ends_with(".loki") && name.len() > 5
}

pub fn parse_loki_name(name: &str) -> Result<&str, DnsError> {
    if !is_loki_name(name) {
        return Err(DnsError::NotLokiName(name.to_string()));
    }
    let host_part = &name[..name.len() - 5];
    if host_part.is_empty() {
        return Err(DnsError::InvalidCharacters(name.to_string()));
    }
    if !host_part
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(DnsError::InvalidCharacters(name.to_string()));
    }
    Ok(host_part)
}

/// Trait for querying the DHT for intro-set entries by target public key.
pub trait DhtClient: Send + Sync {
    fn lookup_intro_set(&self, target: &PublicKey) -> Vec<DhtIntroResult>;
}

#[derive(Debug, Clone)]
pub struct DhtIntroResult {
    pub public_key: PublicKey,
    pub addresses: Vec<String>,
}
