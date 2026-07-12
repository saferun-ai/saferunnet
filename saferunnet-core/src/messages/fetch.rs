/// Fetch messages for router contacts and router IDs, ported from
/// Lokinet C++ `llarp/messages/fetch.hpp`.
///
/// C++ namespaces: `llarp::FetchRC` and `llarp::FetchRID`.
use crate::contact::RouterId;
use super::common::serialize_status_response;

/// Error prefix for invalid fetch requests.
/// C++: `llarp::FetchRC::INVALID_REQUEST`.
use std::sync::LazyLock;
pub static INVALID_REQUEST: LazyLock<String> =
    LazyLock::new(|| serialize_status_response("Invalid relay ID requested"));

/// Error type for fetch message (de)serialization.
#[derive(Debug, thiserror::Error)]
pub enum FetchMessageError {
    #[error("fetch message payload truncated")]
    Truncated,
    #[error("unsupported fetch message version `{0}`")]
    UnsupportedVersion(u8),
    #[error("too many keys: {count} (max {max})")]
    TooManyKeys { count: usize, max: usize },
}

const MAX_FETCH_KEYS: usize = 256;

// ── FetchRCs ──────────────────────────────────────────────────────
/// Request router contacts for a list of RouterIds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRCs {
    /// RouterIds to fetch RC data for.
    pub keys: Vec<RouterId>,
}

const FETCH_RCS_VERSION: u8 = 1;

impl FetchRCs {
    pub fn encode(&self) -> Result<Vec<u8>, FetchMessageError> {
        if self.keys.len() > MAX_FETCH_KEYS {
            return Err(FetchMessageError::TooManyKeys {
                count: self.keys.len(),
                max: MAX_FETCH_KEYS,
            });
        }
        let count = u16::try_from(self.keys.len()).map_err(|_| {
            FetchMessageError::TooManyKeys {
                count: self.keys.len(),
                max: MAX_FETCH_KEYS,
            }
        })?;
        let mut buf = Vec::with_capacity(1 + 2 + self.keys.len() * 32);
        buf.push(FETCH_RCS_VERSION);
        buf.extend_from_slice(&count.to_be_bytes());
        for key in &self.keys {
            buf.extend_from_slice(key.as_bytes());
        }
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self, FetchMessageError> {
        if data.len() < 1 + 2 {
            return Err(FetchMessageError::Truncated);
        }
        let mut cursor = data;
        let version = take_byte(&mut cursor)?;
        if version != FETCH_RCS_VERSION {
            return Err(FetchMessageError::UnsupportedVersion(version));
        }
        let count = u16::from_be_bytes(take_slice(&mut cursor, 2)?.try_into().unwrap()) as usize;
        if count > MAX_FETCH_KEYS {
            return Err(FetchMessageError::TooManyKeys {
                count,
                max: MAX_FETCH_KEYS,
            });
        }
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            let mut rid = [0u8; 32];
            rid.copy_from_slice(take_slice(&mut cursor, 32)?);
            keys.push(RouterId::from_bytes(rid));
        }
        Ok(Self { keys })
    }
}

/// Response to a `FetchRCs` request — one payload blob per requested RouterId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRCsResponse {
    /// RC payloads (each corresponds positionally to a requested RouterId).
    pub rcs: Vec<Vec<u8>>,
}

const FETCH_RCS_RESPONSE_VERSION: u8 = 1;

impl FetchRCsResponse {
    pub fn encode(&self) -> Result<Vec<u8>, FetchMessageError> {
        let count = u16::try_from(self.rcs.len()).map_err(|_| {
            FetchMessageError::TooManyKeys {
                count: self.rcs.len(),
                max: MAX_FETCH_KEYS,
            }
        })?;
        let mut buf = Vec::new();
        buf.push(FETCH_RCS_RESPONSE_VERSION);
        buf.extend_from_slice(&count.to_be_bytes());
        for rc in &self.rcs {
            let len = u16::try_from(rc.len()).map_err(|_| FetchMessageError::Truncated)?;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(rc);
        }
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self, FetchMessageError> {
        if data.len() < 1 + 2 {
            return Err(FetchMessageError::Truncated);
        }
        let mut cursor = data;
        let version = take_byte(&mut cursor)?;
        if version != FETCH_RCS_RESPONSE_VERSION {
            return Err(FetchMessageError::UnsupportedVersion(version));
        }
        let count = u16::from_be_bytes(take_slice(&mut cursor, 2)?.try_into().unwrap()) as usize;
        let mut rcs = Vec::with_capacity(count);
        for _ in 0..count {
            if cursor.len() < 2 {
                return Err(FetchMessageError::Truncated);
            }
            let len =
                u16::from_be_bytes(take_slice(&mut cursor, 2)?.try_into().unwrap()) as usize;
            rcs.push(take_slice(&mut cursor, len)?.to_vec());
        }
        Ok(Self { rcs })
    }
}

// ── FetchRIDs ─────────────────────────────────────────────────────
/// Request all known RouterIds (empty body — just the version byte).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchRIDs;

const FETCH_RIDS_VERSION: u8 = 1;

impl FetchRIDs {
    pub fn encode(&self) -> Vec<u8> {
        vec![FETCH_RIDS_VERSION]
    }

    pub fn decode(data: &[u8]) -> Result<Self, FetchMessageError> {
        if data.is_empty() {
            return Err(FetchMessageError::Truncated);
        }
        let version = data[0];
        if version != FETCH_RIDS_VERSION {
            return Err(FetchMessageError::UnsupportedVersion(version));
        }
        Ok(Self)
    }
}

/// Response to a `FetchRIDs` request — the full list of known RouterIds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRIDsResponse {
    pub rids: Vec<RouterId>,
}

const FETCH_RIDS_RESPONSE_VERSION: u8 = 1;

impl FetchRIDsResponse {
    pub fn encode(&self) -> Result<Vec<u8>, FetchMessageError> {
        let count = u16::try_from(self.rids.len()).map_err(|_| {
            FetchMessageError::TooManyKeys {
                count: self.rids.len(),
                max: MAX_FETCH_KEYS,
            }
        })?;
        let mut buf = Vec::with_capacity(1 + 2 + self.rids.len() * 32);
        buf.push(FETCH_RIDS_RESPONSE_VERSION);
        buf.extend_from_slice(&count.to_be_bytes());
        for rid in &self.rids {
            buf.extend_from_slice(rid.as_bytes());
        }
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self, FetchMessageError> {
        if data.len() < 1 + 2 {
            return Err(FetchMessageError::Truncated);
        }
        let mut cursor = data;
        let version = take_byte(&mut cursor)?;
        if version != FETCH_RIDS_RESPONSE_VERSION {
            return Err(FetchMessageError::UnsupportedVersion(version));
        }
        let count = u16::from_be_bytes(take_slice(&mut cursor, 2)?.try_into().unwrap()) as usize;
        if count > MAX_FETCH_KEYS {
            return Err(FetchMessageError::TooManyKeys {
                count,
                max: MAX_FETCH_KEYS,
            });
        }
        let mut rids = Vec::with_capacity(count);
        for _ in 0..count {
            let mut rid = [0u8; 32];
            rid.copy_from_slice(take_slice(&mut cursor, 32)?);
            rids.push(RouterId::from_bytes(rid));
        }
        Ok(Self { rids })
    }
}

// ── Helpers ───────────────────────────────────────────────────────
fn take_byte<'a>(cursor: &mut &'a [u8]) -> Result<u8, FetchMessageError> {
    if cursor.is_empty() {
        return Err(FetchMessageError::Truncated);
    }
    let b = cursor[0];
    *cursor = &cursor[1..];
    Ok(b)
}

fn take_slice<'a>(
    cursor: &mut &'a [u8],
    len: usize,
) -> Result<&'a [u8], FetchMessageError> {
    if cursor.len() < len {
        return Err(FetchMessageError::Truncated);
    }
    let (head, tail) = cursor.split_at(len);
    *cursor = tail;
    Ok(head)
}

// ── Tests ─────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_rcs_roundtrip() {
        let msg = FetchRCs {
            keys: vec![
                RouterId::from_bytes([0x01; 32]),
                RouterId::from_bytes([0x02; 32]),
                RouterId::from_bytes([0x03; 32]),
            ],
        };
        let encoded = msg.encode().expect("encode");
        let decoded = FetchRCs::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_fetch_rcs_empty() {
        let msg = FetchRCs { keys: vec![] };
        let encoded = msg.encode().expect("encode");
        let decoded = FetchRCs::decode(&encoded).expect("decode");
        assert!(decoded.keys.is_empty());
    }

    #[test]
    fn test_fetch_rcs_response_roundtrip() {
        let msg = FetchRCsResponse {
            rcs: vec![
                vec![0xAA; 10],
                vec![0xBB; 20],
            ],
        };
        let encoded = msg.encode().expect("encode");
        let decoded = FetchRCsResponse::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_fetch_rcs_response_empty() {
        let msg = FetchRCsResponse { rcs: vec![] };
        let encoded = msg.encode().expect("encode");
        let decoded = FetchRCsResponse::decode(&encoded).expect("decode");
        assert!(decoded.rcs.is_empty());
    }

    #[test]
    fn test_fetch_rids_roundtrip() {
        let msg = FetchRIDs;
        let encoded = msg.encode();
        let decoded = FetchRIDs::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_fetch_rids_response_roundtrip() {
        let msg = FetchRIDsResponse {
            rids: vec![
                RouterId::from_bytes([0x10; 32]),
                RouterId::from_bytes([0x20; 32]),
            ],
        };
        let encoded = msg.encode().expect("encode");
        let decoded = FetchRIDsResponse::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_fetch_truncated_decode() {
        assert!(FetchRCs::decode(&[]).is_err());
        assert!(FetchRCsResponse::decode(&[]).is_err());
        assert!(FetchRIDs::decode(&[]).is_err());
        assert!(FetchRIDsResponse::decode(&[]).is_err());
    }

    #[test]
    fn test_invalid_request_constant() {
        assert_eq!(&*INVALID_REQUEST, "!Invalid relay ID requested");
    }
}
