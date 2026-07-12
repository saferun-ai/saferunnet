/// Path build / latency / switch messages, ported from Lokinet C++ `llarp/messages/path.hpp`.
///
/// C++ namespaces mapped:
/// - `llarp::PATH::BUILD` → `build` sub‑module
/// - `llarp::PATH::CONTROL` / `llarp::PATH::DATA` → encoded here as needed
use crate::contact::RouterId;
use thiserror::Error;

// ── Path‑build constants ──────────────────────────────────────────
/// Status responses emitted during path‑build handshake failures.
/// C++: `llarp::PATH::BUILD::NO_TRANSIT` etc.
pub mod build {
    use super::serialize_status_response;
    use std::sync::LazyLock;

    macro_rules! build_response {
        ($name:ident, $msg:literal) => {
        pub static $name: LazyLock<String> =
            LazyLock::new(|| serialize_status_response($msg));
        };
    }

    build_response!(NO_TRANSIT, "NOT ALLOWING TRANSIT");
    build_response!(BAD_LIFETIME, "BAD PATH LIFETIME (TOO LONG)");
    build_response!(BAD_FRAMES, "BAD FRAMES");
    build_response!(BAD_PATHID, "BAD PATH ID");
    build_response!(BAD_CRYPTO, "BAD CRYPTO");
}

// ── TransitHop stub for path‑build serialization ──────────────────
/// A minimal transit‑hop representation for path‑build messages.
/// C++: `llarp::path::TransitHop` (simplified — the full struct carries
/// shared_secret, txid, nonce, upstream_router_id, downstream_router_id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathBuildHop {
    /// Upstream router public key (32 bytes).
    pub upstream: [u8; 32],
    /// Downstream router identifier.
    pub downstream: RouterId,
    /// Symmetric nonce (24 bytes for XChaCha20).
    pub nonce: [u8; 24],
    /// Encrypted inner payload.
    pub encrypted_payload: Vec<u8>,
}

const PATH_BUILD_HOP_VERSION: u8 = 1;

/// Encode a single transit hop for the path‑build onion.
/// Wire format: `version(1) | upstream(32) | downstream(32) | nonce(24) | payload_len(u16) | payload`
pub fn serialize_path_build(hop: &PathBuildHop) -> Vec<u8> {
    let payload_len = u16::try_from(hop.encrypted_payload.len()).unwrap_or(u16::MAX);
    let mut buf = Vec::with_capacity(1 + 32 + 32 + 24 + 2 + hop.encrypted_payload.len());
    buf.push(PATH_BUILD_HOP_VERSION);
    buf.extend_from_slice(&hop.upstream);
    buf.extend_from_slice(hop.downstream.as_bytes());
    buf.extend_from_slice(&hop.nonce);
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.extend_from_slice(&hop.encrypted_payload);
    buf
}

/// Error variants for path‑build (de)serialization.
#[derive(Debug, Error)]
pub enum PathBuildError {
    #[error("path-build hop payload truncated")]
    Truncated,
    #[error("unsupported path-build hop version `{0}`")]
    UnsupportedVersion(u8),
    #[error("path-build hop payload too large: {found} (max {max})")]
    PayloadTooLarge { max: usize, found: usize },
}

/// Decode a transit hop from a path‑build message.
pub fn deserialize_path_build(data: &[u8]) -> Result<PathBuildHop, PathBuildError> {
    let min_len = 1 + 32 + 32 + 24 + 2;
    if data.len() < min_len {
        return Err(PathBuildError::Truncated);
    }
    let mut cursor = data;
    let version = take_byte(&mut cursor)?;
    if version != PATH_BUILD_HOP_VERSION {
        return Err(PathBuildError::UnsupportedVersion(version));
    }

    let mut upstream = [0u8; 32];
    upstream.copy_from_slice(take_slice(&mut cursor, 32)?);
    let mut downstream_raw = [0u8; 32];
    downstream_raw.copy_from_slice(take_slice(&mut cursor, 32)?);
    let downstream = RouterId::from_bytes(downstream_raw);

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(take_slice(&mut cursor, 24)?);

    let payload_len = u16::from_be_bytes(
        take_slice(&mut cursor, 2)?
            .try_into()
            .expect("exact 2 bytes"),
    ) as usize;

    if payload_len > cursor.len() {
        return Err(PathBuildError::PayloadTooLarge {
            max: cursor.len(),
            found: payload_len,
        });
    }

    let encrypted_payload = take_slice(&mut cursor, payload_len)?.to_vec();

    Ok(PathBuildHop {
        upstream,
        downstream,
        nonce,
        encrypted_payload,
    })
}

// ── Path latency message ──────────────────────────────────────────
/// Simple latency‑measurement message sent along a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathLatencyMessage {
    /// Path identifier.
    pub path_id: u64,
    /// Monotonic timestamp (milliseconds).
    pub timestamp_ms: u64,
    /// Sequence number for deduplication.
    pub sequence: u32,
}

const PATH_LATENCY_VERSION: u8 = 1;

impl PathLatencyMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 8 + 8 + 4);
        buf.push(PATH_LATENCY_VERSION);
        buf.extend_from_slice(&self.path_id.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, PathBuildError> {
        if data.len() < 1 + 8 + 8 + 4 {
            return Err(PathBuildError::Truncated);
        }
        let mut cursor = data;
        let version = take_byte(&mut cursor)?;
        if version != PATH_LATENCY_VERSION {
            return Err(PathBuildError::UnsupportedVersion(version));
        }
        let path_id = u64::from_be_bytes(take_slice(&mut cursor, 8)?.try_into().unwrap());
        let timestamp_ms = u64::from_be_bytes(take_slice(&mut cursor, 8)?.try_into().unwrap());
        let sequence = u32::from_be_bytes(take_slice(&mut cursor, 4)?.try_into().unwrap());
        Ok(Self {
            path_id,
            timestamp_ms,
            sequence,
        })
    }
}

// ── Path switch message ───────────────────────────────────────────
/// Instruct the remote to migrate a session from `old_path` to `new_path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSwitchMessage {
    /// Current (old) path identifier.
    pub old_path: u64,
    /// Target (new) path identifier.
    pub new_path: u64,
}

const PATH_SWITCH_VERSION: u8 = 1;

impl PathSwitchMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 8 + 8);
        buf.push(PATH_SWITCH_VERSION);
        buf.extend_from_slice(&self.old_path.to_be_bytes());
        buf.extend_from_slice(&self.new_path.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, PathBuildError> {
        if data.len() < 1 + 8 + 8 {
            return Err(PathBuildError::Truncated);
        }
        let mut cursor = data;
        let version = take_byte(&mut cursor)?;
        if version != PATH_SWITCH_VERSION {
            return Err(PathBuildError::UnsupportedVersion(version));
        }
        let old_path = u64::from_be_bytes(take_slice(&mut cursor, 8)?.try_into().unwrap());
        let new_path = u64::from_be_bytes(take_slice(&mut cursor, 8)?.try_into().unwrap());
        Ok(Self { old_path, new_path })
    }
}

// ── Helpers ───────────────────────────────────────────────────────
fn take_byte<'a>(cursor: &mut &'a [u8]) -> Result<u8, PathBuildError> {
    if cursor.is_empty() {
        return Err(PathBuildError::Truncated);
    }
    let b = cursor[0];
    *cursor = &cursor[1..];
    Ok(b)
}

fn take_slice<'a>(cursor: &mut &'a [u8], len: usize) -> Result<&'a [u8], PathBuildError> {
    if cursor.len() < len {
        return Err(PathBuildError::Truncated);
    }
    let (head, tail) = cursor.split_at(len);
    *cursor = tail;
    Ok(head)
}

use super::common::serialize_status_response;

// ── Tests ─────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── Path‑build constants ──────────────────────────────────
    #[test]
    fn test_build_constants() {
        assert_eq!(&*build::NO_TRANSIT, "!NOT ALLOWING TRANSIT");
        assert_eq!(&*build::BAD_LIFETIME, "!BAD PATH LIFETIME (TOO LONG)");
        assert_eq!(&*build::BAD_FRAMES, "!BAD FRAMES");
        assert_eq!(&*build::BAD_PATHID, "!BAD PATH ID");
        assert_eq!(&*build::BAD_CRYPTO, "!BAD CRYPTO");
    }

    // ── PathBuildHop round‑trip ───────────────────────────────
    #[test]
    fn test_path_build_encode_decode_roundtrip() {
        let hop = PathBuildHop {
            upstream: [0xAA; 32],
            downstream: RouterId::from_bytes([0xBB; 32]),
            nonce: [0xCC; 24],
            encrypted_payload: vec![0xDD; 64],
        };
        let encoded = serialize_path_build(&hop);
        let decoded = deserialize_path_build(&encoded).expect("roundtrip");
        assert_eq!(hop, decoded);
    }

    #[test]
    fn test_path_build_empty_payload() {
        let hop = PathBuildHop {
            upstream: [0x11; 32],
            downstream: RouterId::from_bytes([0x22; 32]),
            nonce: [0x33; 24],
            encrypted_payload: Vec::<u8>::new(),
        };
        let encoded = serialize_path_build(&hop);
        let decoded = deserialize_path_build(&encoded).expect("empty payload");
        assert_eq!(decoded.encrypted_payload, Vec::<u8>::new());
    }

    #[test]
    fn test_path_build_decode_truncated() {
        assert!(deserialize_path_build(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn test_path_build_decode_wrong_version() {
        let hop = PathBuildHop {
            upstream: [0; 32],
            downstream: RouterId::from_bytes([0; 32]),
            nonce: [0; 24],
            encrypted_payload: Vec::<u8>::new(),
        };
        let mut encoded = serialize_path_build(&hop);
        encoded[0] = 99; // corrupt version
        assert!(matches!(
            deserialize_path_build(&encoded),
            Err(PathBuildError::UnsupportedVersion(99))
        ));
    }

    // ── PathLatencyMessage ────────────────────────────────────
    #[test]
    fn test_latency_message_roundtrip() {
        let msg = PathLatencyMessage {
            path_id: 0xDEAD_BEEF_CAFE_BABE,
            timestamp_ms: 1_700_000_000_000,
            sequence: 42,
        };
        let encoded = msg.encode();
        let decoded = PathLatencyMessage::decode(&encoded).expect("latency decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_latency_message_truncated() {
        assert!(PathLatencyMessage::decode(&[]).is_err());
        assert!(PathLatencyMessage::decode(&[1, 2, 3]).is_err());
    }

    // ── PathSwitchMessage ─────────────────────────────────────
    #[test]
    fn test_switch_message_roundtrip() {
        let msg = PathSwitchMessage {
            old_path: 100,
            new_path: 200,
        };
        let encoded = msg.encode();
        let decoded = PathSwitchMessage::decode(&encoded).expect("switch decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_switch_message_truncated() {
        assert!(PathSwitchMessage::decode(&[]).is_err());
        assert!(PathSwitchMessage::decode(&[1]).is_err());
    }
}
