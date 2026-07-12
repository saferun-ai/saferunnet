/// DHT messages, ported from Lokinet C++ `llarp/messages/dht.hpp`.
///
/// Encodes/decodes `PublishClientContact` (~PublishCC), `FindClientContact` (~FindCC),
/// and `FindClientContactResponse`.
use crate::contact::RouterId;
use thiserror::Error;

use super::common::serialize_status_response;

// ── DHT status constants ──────────────────────────────────────────
pub mod status {
    use super::serialize_status_response;
    use std::sync::LazyLock;

    macro_rules! dht_response {
        ($name:ident, $msg:literal) => {
            pub static $name: LazyLock<String> =
                LazyLock::new(|| serialize_status_response($msg));
        };
    }

    dht_response!(INVALID, "INVALID CC");
    dht_response!(EXPIRED, "EXPIRED CC");
    dht_response!(NOT_FOUND, "NOT FOUND");
    dht_response!(INSUFFICIENT, "INSUFFICIENT NODES");
    dht_response!(INVALID_ORDER, "INVALID ORDER");
}

/// Error type for DHT message (de)serialization.
#[derive(Debug, Error)]
pub enum DhtMessageError {
    #[error("DHT message payload truncated")]
    Truncated,
    #[error("unsupported DHT message version `{0}`")]
    UnsupportedVersion(u8),
    #[error("DHT message field length overflow: {field} = {length}")]
    LengthOverflow { field: &'static str, length: usize },
}

// ── PublishClientContact ─────────────────────────────────────────
/// Publish an encrypted client contact to the DHT.
/// C++: `llarp::PublishClientContact::serialize()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishCC {
    /// The DHT key under which the contact is published.
    pub key: Vec<u8>,
    /// Encrypted client contact payload.
    pub data: Vec<u8>,
    /// Optional RouterID of the sender (only set on session paths).
    pub sender: Option<RouterId>,
}

const PUBLISH_CC_VERSION: u8 = 1;

impl PublishCC {
    pub fn encode(&self) -> Result<Vec<u8>, DhtMessageError> {
        let key_len =
            u16::try_from(self.key.len()).map_err(|_| DhtMessageError::LengthOverflow {
                field: "key",
                length: self.key.len(),
            })?;
        let data_len =
            u16::try_from(self.data.len()).map_err(|_| DhtMessageError::LengthOverflow {
                field: "data",
                length: self.data.len(),
            })?;
        let has_sender = self.sender.is_some() as u8;
        let mut buf = Vec::with_capacity(1 + 2 + self.key.len() + 2 + self.data.len() + 1 + 32);
        buf.push(PUBLISH_CC_VERSION);
        buf.push(has_sender);
        buf.extend_from_slice(&key_len.to_be_bytes());
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(&data_len.to_be_bytes());
        buf.extend_from_slice(&self.data);
        if let Some(ref sender) = self.sender {
            buf.extend_from_slice(sender.as_bytes());
        }
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self, DhtMessageError> {
        if data.len() < 1 + 1 + 2 {
            return Err(DhtMessageError::Truncated);
        }
        let mut cursor = data;
        let version = take_byte(&mut cursor)?;
        if version != PUBLISH_CC_VERSION {
            return Err(DhtMessageError::UnsupportedVersion(version));
        }
        let has_sender = take_byte(&mut cursor)?;

        let key_len = u16::from_be_bytes(take_slice(&mut cursor, 2)?.try_into().unwrap()) as usize;
        let key = take_slice(&mut cursor, key_len)?.to_vec();

        let data_len = u16::from_be_bytes(take_slice(&mut cursor, 2)?.try_into().unwrap()) as usize;
        let data = take_slice(&mut cursor, data_len)?.to_vec();

        let sender = if has_sender != 0 {
            let mut rid = [0u8; 32];
            rid.copy_from_slice(take_slice(&mut cursor, 32)?);
            Some(RouterId::from_bytes(rid))
        } else {
            None
        };

        Ok(Self { key, data, sender })
    }
}

// ── FindClientContact ─────────────────────────────────────────────
/// Look up a client contact by DHT key.
/// C++: `llarp::FindClientContact::serialize()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindCC {
    /// The DHT key to look up.
    pub key: Vec<u8>,
}

const FIND_CC_VERSION: u8 = 1;

impl FindCC {
    pub fn encode(&self) -> Result<Vec<u8>, DhtMessageError> {
        let key_len =
            u16::try_from(self.key.len()).map_err(|_| DhtMessageError::LengthOverflow {
                field: "key",
                length: self.key.len(),
            })?;
        let mut buf = Vec::with_capacity(1 + 2 + self.key.len());
        buf.push(FIND_CC_VERSION);
        buf.extend_from_slice(&key_len.to_be_bytes());
        buf.extend_from_slice(&self.key);
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self, DhtMessageError> {
        if data.len() < 1 + 2 {
            return Err(DhtMessageError::Truncated);
        }
        let mut cursor = data;
        let version = take_byte(&mut cursor)?;
        if version != FIND_CC_VERSION {
            return Err(DhtMessageError::UnsupportedVersion(version));
        }
        let key_len = u16::from_be_bytes(take_slice(&mut cursor, 2)?.try_into().unwrap()) as usize;
        let key = take_slice(&mut cursor, key_len)?.to_vec();
        Ok(Self { key })
    }
}

/// Response to a `FindCC` request — a list of encrypted client contacts.
/// C++: `llarp::FindClientContact::serialize_response()` / `deserialize_response()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindCCResponse {
    /// One or more encrypted client contact payloads.
    pub results: Vec<Vec<u8>>,
}

const FIND_CC_RESPONSE_VERSION: u8 = 1;

impl FindCCResponse {
    pub fn encode(&self) -> Result<Vec<u8>, DhtMessageError> {
        let count = u16::try_from(self.results.len()).map_err(|_| {
            DhtMessageError::LengthOverflow {
                field: "results",
                length: self.results.len(),
            }
        })?;
        let mut buf = Vec::new();
        buf.push(FIND_CC_RESPONSE_VERSION);
        buf.extend_from_slice(&count.to_be_bytes());
        for result in &self.results {
            let len = u16::try_from(result.len()).map_err(|_| {
                DhtMessageError::LengthOverflow {
                    field: "result item",
                    length: result.len(),
                }
            })?;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(result);
        }
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self, DhtMessageError> {
        if data.len() < 1 + 2 {
            return Err(DhtMessageError::Truncated);
        }
        let mut cursor = data;
        let version = take_byte(&mut cursor)?;
        if version != FIND_CC_RESPONSE_VERSION {
            return Err(DhtMessageError::UnsupportedVersion(version));
        }
        let count = u16::from_be_bytes(take_slice(&mut cursor, 2)?.try_into().unwrap()) as usize;
        let mut results = Vec::with_capacity(count);
        for _ in 0..count {
            if cursor.len() < 2 {
                return Err(DhtMessageError::Truncated);
            }
            let len =
                u16::from_be_bytes(take_slice(&mut cursor, 2)?.try_into().unwrap()) as usize;
            results.push(take_slice(&mut cursor, len)?.to_vec());
        }
        Ok(Self { results })
    }
}

// ── Helpers ───────────────────────────────────────────────────────
fn take_byte<'a>(cursor: &mut &'a [u8]) -> Result<u8, DhtMessageError> {
    if cursor.is_empty() {
        return Err(DhtMessageError::Truncated);
    }
    let b = cursor[0];
    *cursor = &cursor[1..];
    Ok(b)
}

fn take_slice<'a>(
    cursor: &mut &'a [u8],
    len: usize,
) -> Result<&'a [u8], DhtMessageError> {
    if cursor.len() < len {
        return Err(DhtMessageError::Truncated);
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
    fn test_publish_cc_roundtrip_no_sender() {
        let msg = PublishCC {
            key: vec![0x01, 0x02, 0x03],
            data: vec![0xFF; 128],
            sender: None,
        };
        let encoded = msg.encode().expect("encode");
        let decoded = PublishCC::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_publish_cc_roundtrip_with_sender() {
        let msg = PublishCC {
            key: b"dht-key-32-bytes-long-string!!".to_vec(),
            data: vec![0xAB; 64],
            sender: Some(RouterId::from_bytes([0xCD; 32])),
        };
        let encoded = msg.encode().expect("encode");
        let decoded = PublishCC::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_find_cc_roundtrip() {
        let msg = FindCC {
            key: vec![0x11, 0x22, 0x33, 0x44],
        };
        let encoded = msg.encode().expect("encode");
        let decoded = FindCC::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_find_cc_response_roundtrip() {
        let msg = FindCCResponse {
            results: vec![
                b"contact-1".to_vec(),
                b"contact-2-with-longer-data".to_vec(),
                vec![],
            ],
        };
        let encoded = msg.encode().expect("encode");
        let decoded = FindCCResponse::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_find_cc_response_empty() {
        let msg = FindCCResponse { results: vec![] };
        let encoded = msg.encode().expect("encode");
        let decoded = FindCCResponse::decode(&encoded).expect("decode");
        assert!(decoded.results.is_empty());
    }

    #[test]
    fn test_find_cc_truncated() {
        assert!(FindCC::decode(&[]).is_err());
        assert!(FindCC::decode(&[1]).is_err());
    }

    #[test]
    fn test_dht_status_constants() {
        assert_eq!(&*status::INVALID, "!INVALID CC");
        assert_eq!(&*status::EXPIRED, "!EXPIRED CC");
        assert_eq!(&*status::NOT_FOUND, "!NOT FOUND");
        assert_eq!(&*status::INSUFFICIENT, "!INSUFFICIENT NODES");
        assert_eq!(&*status::INVALID_ORDER, "!INVALID ORDER");
    }
}
