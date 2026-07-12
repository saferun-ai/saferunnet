use saferunnet_crypto::PublicKey;
use thiserror::Error;

/// Recognised SaferunNet domain suffixes.
pub const SAFERUNNET_SUFFIXES: &[&str] = &[".loki", ".snode", ".sfr"];

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("not a SaferunNet name: {0}")]
    NotLokiName(String),
    #[error("invalid name characters: {0}")]
    InvalidCharacters(String),
    #[error("name not found: {0}")]
    NotFound(String),
}

pub trait LokiResolver {
    fn resolve(&self, name: &str) -> Result<Vec<PublicKey>, DnsError>;
}

/// Return the matching suffix if `name` ends with a known SaferunNet suffix.
pub fn saferunnet_suffix(name: &str) -> Option<&'static str> {
    SAFERUNNET_SUFFIXES.iter().find(|s| name.ends_with(*s)).copied()
}

/// True when the name matches any SaferunNet suffix (`.loki`, `.snode`, `.sfr`).
pub fn is_saferunnet_name(name: &str) -> bool {
    saferunnet_suffix(name).is_some()
}

/// Backward-compatible alias.
#[deprecated(note = "use `is_saferunnet_name`")]
pub fn is_loki_name(name: &str) -> bool {
    is_saferunnet_name(name)
}

/// Strip the recognised suffix from a SaferunNet name, returning the host portion.
pub fn strip_saferunnet_suffix(name: &str) -> Option<&str> {
    saferunnet_suffix(name).map(|s| &name[..name.len() - s.len()])
}

pub fn parse_loki_name(name: &str) -> Result<&str, DnsError> {
    if !is_saferunnet_name(name) {
        return Err(DnsError::NotLokiName(name.to_string()));
    }
    let host_part = strip_saferunnet_suffix(name).unwrap_or(name);
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
