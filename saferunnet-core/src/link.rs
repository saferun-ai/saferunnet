use thiserror::Error;
use std::net::SocketAddr;
 use std::sync::Arc;
 use tokio::sync::RwLock;
 use crate::transport::{LinkTransport, TransportError};


/// Maximum payload size for a single LLARP frame.
pub const MAX_FRAME_PAYLOAD: usize = 1024;

const LLARP_VERSION: u8 = 1;
const LLARP_HEADER_LEN: usize = 13;

/// LLARP frame kind — the four core link-layer message families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Control messages (ping, close, path-switch).
    Control = 1,
    /// Relay-intro: first-hop node receives this to learn the next hop.
    RelayIntro = 2,
    /// Relay-data: transit data with onion-encrypted payload.
    RelayData = 3,
    /// Session data: end-to-end traffic inside an established path.
    SessionData = 4,
}

impl FrameKind {
    pub fn from_byte(b: u8) -> Result<Self, FrameCodecError> {
        match b {
            1 => Ok(Self::Control),
            2 => Ok(Self::RelayIntro),
            3 => Ok(Self::RelayData),
            4 => Ok(Self::SessionData),
            _ => Err(FrameCodecError::UnsupportedFrameKind(b)),
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// A fully-decoded LLARP wire frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlarpFrame {
    pub kind: FrameKind,
    pub path_id: u64,
    pub hop_index: u8,
    pub payload: Vec<u8>,
}

impl LlarpFrame {
    /// Create a new LLARP frame.
    pub fn new(
        kind: FrameKind,
        path_id: u64,
        hop_index: u8,
        payload: Vec<u8>,
    ) -> Result<Self, FrameCodecError> {
        if payload.len() > MAX_FRAME_PAYLOAD {
            return Err(FrameCodecError::PayloadTooLarge {
                max: MAX_FRAME_PAYLOAD,
                found: payload.len(),
            });
        }
        Ok(Self {
            kind,
            path_id,
            hop_index,
            payload,
        })
    }

    /// Encode the frame to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(LLARP_HEADER_LEN + self.payload.len());
        buf.push(LLARP_VERSION);
        buf.push(self.kind.to_byte());
        buf.extend_from_slice(&self.path_id.to_be_bytes());
        buf.push(self.hop_index);
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode a frame from wire bytes.
    pub fn decode(input: &[u8]) -> Result<Self, FrameCodecError> {
        if input.len() < LLARP_HEADER_LEN {
            return Err(FrameCodecError::Truncated);
        }

        let mut cursor = input;
        let version = take_exact(&mut cursor, 1)?[0];
        if version != LLARP_VERSION {
            return Err(FrameCodecError::UnsupportedVersion(version));
        }

        let kind = FrameKind::from_byte(take_exact(&mut cursor, 1)?[0])?;

        let path_id = u64::from_be_bytes(
            take_exact(&mut cursor, 8)?
                .try_into()
                .expect("take_exact guarantees exact byte count"),
        );

        let hop_index = take_exact(&mut cursor, 1)?[0];

        let payload_len = u16::from_be_bytes(
            take_exact(&mut cursor, 2)?
                .try_into()
                .expect("take_exact guarantees exact byte count"),
        ) as usize;

        if payload_len > MAX_FRAME_PAYLOAD {
            return Err(FrameCodecError::PayloadTooLarge {
                max: MAX_FRAME_PAYLOAD,
                found: payload_len,
            });
        }

        if cursor.len() < payload_len {
            return Err(FrameCodecError::PayloadLengthMismatch {
                declared: payload_len,
                remaining: cursor.len(),
            });
        }

        let payload = take_exact(&mut cursor, payload_len)?.to_vec();

        if !cursor.is_empty() {
            return Err(FrameCodecError::TrailingBytes(cursor.len()));
        }

        Ok(Self {
            kind,
            path_id,
            hop_index,
            payload,
        })
    }
}

#[derive(Debug, Error)]
pub enum FrameCodecError {
    #[error("unsupported LLARP frame version `{0}`")]
    UnsupportedVersion(u8),
    #[error("unsupported LLARP frame kind byte `{0}`")]
    UnsupportedFrameKind(u8),
    #[error("LLARP frame payload exceeds maximum of {max} (got {found})")]
    PayloadTooLarge { max: usize, found: usize },
    #[error("LLARP frame truncated")]
    Truncated,
    #[error(
        "LLARP frame declared payload length {declared} does not match remaining data {remaining}"
    )]
    PayloadLengthMismatch { declared: usize, remaining: usize },
    #[error("LLARP frame has {0} unexpected trailing bytes")]
    TrailingBytes(usize),
}

fn take_exact<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], FrameCodecError> {
    if input.len() < count {
        return Err(FrameCodecError::Truncated);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}


// ── Link Manager ───────────────────────────────────────────────────────────

pub struct LinkManager<T: LinkTransport> {
    transport: Arc<T>,
    listen_addr: RwLock<Option<SocketAddr>>,
    session_count: RwLock<usize>,
}

impl<T: LinkTransport + 'static> LinkManager<T> {
    pub fn new(transport: Arc<T>) -> Self {
        Self { transport, listen_addr: RwLock::new(None), session_count: RwLock::new(0) }
    }
    pub async fn start(&self) -> Result<(), TransportError> { Ok(()) }
    pub async fn stop(&self) -> Result<(), TransportError> { Ok(()) }
    pub fn num_sessions(&self) -> usize { 0 }
    pub fn connected_peers(&self) -> Vec<String> { Vec::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip_control() {
        let frame = LlarpFrame::new(FrameKind::Control, 42, 0, b"hello".to_vec()).unwrap();
        let encoded = frame.encode();
        let decoded = LlarpFrame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_roundtrip_relay_data() {
        let payload = vec![0xAB; 256];
        let frame = LlarpFrame::new(FrameKind::RelayData, 7, 2, payload.clone()).unwrap();
        let encoded = frame.encode();
        let decoded = LlarpFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.kind, FrameKind::RelayData);
        assert_eq!(decoded.path_id, 7);
        assert_eq!(decoded.hop_index, 2);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn encode_decode_roundtrip_session_data() {
        let frame = LlarpFrame::new(FrameKind::SessionData, 1, 3, vec![0xCC; 100]).unwrap();
        let encoded = frame.encode();
        let decoded = LlarpFrame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_roundtrip_relay_intro() {
        let frame =
            LlarpFrame::new(FrameKind::RelayIntro, 99, 0, b"intro_payload".to_vec()).unwrap();
        let encoded = frame.encode();
        let decoded = LlarpFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.kind, FrameKind::RelayIntro);
        assert_eq!(decoded.path_id, 99);
        assert_eq!(decoded.hop_index, 0);
        assert_eq!(decoded.payload, b"intro_payload".to_vec());
    }

    #[test]
    fn all_frame_kinds_roundtrip() {
        let kinds = [
            FrameKind::Control,
            FrameKind::RelayIntro,
            FrameKind::RelayData,
            FrameKind::SessionData,
        ];
        for kind in kinds {
            let frame = LlarpFrame::new(kind, 1, 0, b"test".to_vec()).unwrap();
            let decoded = LlarpFrame::decode(&frame.encode()).unwrap();
            assert_eq!(decoded.kind, kind);
        }
    }

    #[test]
    fn reject_truncated_header() {
        let result = LlarpFrame::decode(&[0x01, 0x02]);
        assert!(matches!(result, Err(FrameCodecError::Truncated)));
    }

    #[test]
    fn reject_unsupported_version() {
        let mut buf = vec![0u8; LLARP_HEADER_LEN];
        buf[0] = 99;
        let result = LlarpFrame::decode(&buf);
        assert!(matches!(
            result,
            Err(FrameCodecError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn reject_unsupported_frame_kind() {
        let mut buf = vec![0u8; LLARP_HEADER_LEN];
        buf[0] = LLARP_VERSION;
        buf[1] = 99;
        let result = LlarpFrame::decode(&buf);
        assert!(matches!(
            result,
            Err(FrameCodecError::UnsupportedFrameKind(99))
        ));
    }

    #[test]
    fn reject_payload_too_large_on_new() {
        let big = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        let result = LlarpFrame::new(FrameKind::Control, 0, 0, big);
        assert!(matches!(
            result,
            Err(FrameCodecError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn reject_payload_length_mismatch() {
        let mut buf = vec![0u8; LLARP_HEADER_LEN + 5];
        buf[0] = LLARP_VERSION;
        buf[1] = FrameKind::Control.to_byte();
        buf[11] = 0x00;
        buf[12] = 100; // declared 100 bytes, but only 5 available
        let result = LlarpFrame::decode(&buf);
        assert!(matches!(
            result,
            Err(FrameCodecError::PayloadLengthMismatch { .. })
        ));
    }

    #[test]
    fn reject_trailing_bytes() {
        let frame = LlarpFrame::new(FrameKind::Control, 0, 0, b"data".to_vec()).unwrap();
        let mut encoded = frame.encode();
        encoded.push(0xFF); // trailing garbage
        let result = LlarpFrame::decode(&encoded);
        assert!(matches!(result, Err(FrameCodecError::TrailingBytes(1))));
    }

    #[test]
    fn empty_payload_roundtrip() {
        let frame = LlarpFrame::new(FrameKind::Control, 0, 0, vec![]).unwrap();
        let encoded = frame.encode();
        let decoded = LlarpFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload.len(), 0);
    }

    #[test]
    fn max_payload_roundtrip() {
        let payload = vec![0x42; MAX_FRAME_PAYLOAD];
        let frame = LlarpFrame::new(FrameKind::RelayData, 5, 1, payload.clone()).unwrap();
        let encoded = frame.encode();
        let decoded = LlarpFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload.len(), MAX_FRAME_PAYLOAD);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn frame_kind_from_byte_all_valid() {
        for b in 1..=4u8 {
            let kind = FrameKind::from_byte(b).unwrap();
            assert_eq!(kind.to_byte(), b);
        }
    }

    #[test]
    fn frame_kind_from_byte_invalid() {
        for b in [0u8, 5, 255] {
            assert!(FrameKind::from_byte(b).is_err());
        }
    }

    #[test]
    fn hop_index_wraps_naturally() {
        // hop_index is u8; verify it's preserved through encode/decode
        for hop in [0u8, 1, 127, 255] {
            let frame = LlarpFrame::new(FrameKind::RelayData, 0, hop, b"x".to_vec()).unwrap();
            let decoded = LlarpFrame::decode(&frame.encode()).unwrap();
            assert_eq!(decoded.hop_index, hop);
        }
    }

    #[test]
    fn path_id_u64_range() {
        for pid in [0u64, 1, u64::MAX / 2, u64::MAX] {
            let frame = LlarpFrame::new(FrameKind::SessionData, pid, 0, b"x".to_vec()).unwrap();
            let decoded = LlarpFrame::decode(&frame.encode()).unwrap();
            assert_eq!(decoded.path_id, pid);
        }
    }
}
