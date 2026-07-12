/// Session control messages, ported from Lokinet C++ `llarp/messages/session.hpp`.
///
/// Encodes/decodes initiate‑session, close‑session, and session‑path‑switch
/// messages using the existing `SessionHopId` and `SessionTag` types.
use crate::contact::RouterId;
use crate::session::{SessionHopId, SessionTag};
use thiserror::Error;

use super::common::serialize_status_response;

// ── InitiateSession ───────────────────────────────────────────────
/// Status responses for session initiation failures.
/// C++: `llarp::InitiateSession::AUTH_ERROR`, `BAD_ROUTE`, `BAD_ADDRESS`.
pub mod initiate {
    use super::serialize_status_response;
    use std::sync::LazyLock;

    macro_rules! init_response {
        ($name:ident, $msg:literal) => {
            pub static $name: LazyLock<String> =
                LazyLock::new(|| serialize_status_response($msg));
        };
    }

    init_response!(AUTH_ERROR, "AUTH ERROR");
    init_response!(BAD_ROUTE, "BAD ROUTE");
    init_response!(BAD_ADDRESS, "BAD ADDRESS");
}

/// Payload for initiating a session to a remote service.
/// C++: `llarp::InitiateSession::serialize()` / `deserialize()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateSession {
    /// RouterID of the initiator.
    pub initiator: RouterId,
    /// Local pivot hop identifier (taken from local ClientIntro).
    pub local_pivot: SessionHopId,
    /// Remote pivot hop identifier (taken from remote`s ClientIntro).
    pub remote_pivot: SessionHopId,
    /// Whether the Tun interface should be used.
    pub use_tun: bool,
    /// Optional authentication token.
    pub auth_token: Option<Vec<u8>>,
}

const SESSION_INIT_VERSION: u8 = 1;
const SESSION_HOP_ID_LEN: usize = 16;

impl InitiateSession {
    pub fn encode(&self) -> Vec<u8> {
        let auth_len = self
            .auth_token
            .as_ref()
            .map(|t| t.len())
            .unwrap_or(0);
        let mut buf = Vec::with_capacity(
            1 + 32 + SESSION_HOP_ID_LEN + SESSION_HOP_ID_LEN + 1 + 2 + auth_len,
        );
        buf.push(SESSION_INIT_VERSION);
        buf.extend_from_slice(self.initiator.as_bytes());
        buf.extend_from_slice(self.local_pivot.as_bytes());
        buf.extend_from_slice(self.remote_pivot.as_bytes());
        buf.push(if self.use_tun { 1 } else { 0 });
        if let Some(ref token) = self.auth_token {
            let len = u16::try_from(token.len()).unwrap_or(u16::MAX);
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(token);
        } else {
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, SessionMessageError> {
        if data.len() < 1 + 32 + SESSION_HOP_ID_LEN + SESSION_HOP_ID_LEN + 1 + 2 {
            return Err(SessionMessageError::Truncated);
        }
        let mut cursor = data;
        let version = take_byte(&mut cursor)?;
        if version != SESSION_INIT_VERSION {
            return Err(SessionMessageError::UnsupportedVersion(version));
        }
        let mut rid_bytes = [0u8; 32];
        rid_bytes.copy_from_slice(take_slice(&mut cursor, 32)?);
        let initiator = RouterId::from_bytes(rid_bytes);

        let mut lp = [0u8; SESSION_HOP_ID_LEN];
        lp.copy_from_slice(take_slice(&mut cursor, SESSION_HOP_ID_LEN)?);
        let local_pivot = SessionHopId::new(lp);

        let mut rp = [0u8; SESSION_HOP_ID_LEN];
        rp.copy_from_slice(take_slice(&mut cursor, SESSION_HOP_ID_LEN)?);
        let remote_pivot = SessionHopId::new(rp);

        let use_tun_byte = take_byte(&mut cursor)?;
        let use_tun = use_tun_byte != 0;

        let auth_len = u16::from_be_bytes(
            take_slice(&mut cursor, 2)?
                .try_into()
                .expect("exact 2 bytes"),
        ) as usize;

        let auth_token = if auth_len > 0 {
            Some(take_slice(&mut cursor, auth_len)?.to_vec())
        } else {
            None
        };

        Ok(Self {
            initiator,
            local_pivot,
            remote_pivot,
            use_tun,
            auth_token,
        })
    }
}

// ── CloseSession ──────────────────────────────────────────────────
/// Payload for closing a previously established session.
/// C++: `llarp::CloseSession::serialize()` / `deserialize()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseSession {
    /// The session tag identifying the session to close.
    pub session_tag: SessionTag,
    /// Human‑readable reason for closure.
    pub reason: String,
}

const SESSION_CLOSE_VERSION: u8 = 1;

impl CloseSession {
    pub fn encode(&self) -> Vec<u8> {
        let reason_bytes = self.reason.as_bytes();
        let reason_len = u16::try_from(reason_bytes.len()).unwrap_or(u16::MAX);
        let mut buf = Vec::with_capacity(1 + 4 + 2 + reason_bytes.len());
        buf.push(SESSION_CLOSE_VERSION);
        buf.extend_from_slice(&self.session_tag.get().to_be_bytes());
        buf.extend_from_slice(&reason_len.to_be_bytes());
        buf.extend_from_slice(reason_bytes);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, SessionMessageError> {
        if data.len() < 1 + 4 + 2 {
            return Err(SessionMessageError::Truncated);
        }
        let mut cursor = data;
        let version = take_byte(&mut cursor)?;
        if version != SESSION_CLOSE_VERSION {
            return Err(SessionMessageError::UnsupportedVersion(version));
        }
        let tag = u32::from_be_bytes(take_slice(&mut cursor, 4)?.try_into().unwrap());
        let reason_len = u16::from_be_bytes(take_slice(&mut cursor, 2)?.try_into().unwrap()) as usize;
        let reason_bytes = take_slice(&mut cursor, reason_len)?;
        let reason = String::from_utf8_lossy(reason_bytes).into_owned();
        Ok(Self {
            session_tag: SessionTag::new(tag),
            reason,
        })
    }
}

// ── PathSwitch ────────────────────────────────────────────────────
/// Instruct the remote to switch a session onto a new path.
/// C++: `llarp::SessionPathSwitch::serialize()` / `deserialize()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPathSwitch {
    /// The session tag identifying the session.
    pub session_tag: SessionTag,
    /// Local pivot hop identifier.
    pub local_pivot: SessionHopId,
    /// Remote pivot hop identifier.
    pub remote_pivot: SessionHopId,
}

const PATH_SWITCH_VERSION: u8 = 1;

impl SessionPathSwitch {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(1 + 4 + SESSION_HOP_ID_LEN + SESSION_HOP_ID_LEN);
        buf.push(PATH_SWITCH_VERSION);
        buf.extend_from_slice(&self.session_tag.get().to_be_bytes());
        buf.extend_from_slice(self.local_pivot.as_bytes());
        buf.extend_from_slice(self.remote_pivot.as_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, SessionMessageError> {
        if data.len() < 1 + 4 + SESSION_HOP_ID_LEN + SESSION_HOP_ID_LEN {
            return Err(SessionMessageError::Truncated);
        }
        let mut cursor = data;
        let version = take_byte(&mut cursor)?;
        if version != PATH_SWITCH_VERSION {
            return Err(SessionMessageError::UnsupportedVersion(version));
        }
        let tag = u32::from_be_bytes(take_slice(&mut cursor, 4)?.try_into().unwrap());

        let mut lp = [0u8; SESSION_HOP_ID_LEN];
        lp.copy_from_slice(take_slice(&mut cursor, SESSION_HOP_ID_LEN)?);
        let local_pivot = SessionHopId::new(lp);

        let mut rp = [0u8; SESSION_HOP_ID_LEN];
        rp.copy_from_slice(take_slice(&mut cursor, SESSION_HOP_ID_LEN)?);
        let remote_pivot = SessionHopId::new(rp);

        Ok(Self {
            session_tag: SessionTag::new(tag),
            local_pivot,
            remote_pivot,
        })
    }
}

// ── Error ─────────────────────────────────────────────────────────
#[derive(Debug, Error)]
pub enum SessionMessageError {
    #[error("session message payload truncated")]
    Truncated,
    #[error("unsupported session message version `{0}`")]
    UnsupportedVersion(u8),
}

// ── Helpers ───────────────────────────────────────────────────────
fn take_byte<'a>(cursor: &mut &'a [u8]) -> Result<u8, SessionMessageError> {
    if cursor.is_empty() {
        return Err(SessionMessageError::Truncated);
    }
    let b = cursor[0];
    *cursor = &cursor[1..];
    Ok(b)
}

fn take_slice<'a>(
    cursor: &mut &'a [u8],
    len: usize,
) -> Result<&'a [u8], SessionMessageError> {
    if cursor.len() < len {
        return Err(SessionMessageError::Truncated);
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
    fn test_initiate_encode_decode_no_auth() {
        let msg = InitiateSession {
            initiator: RouterId::from_bytes([0x01; 32]),
            local_pivot: SessionHopId::new([0x02; 16]),
            remote_pivot: SessionHopId::new([0x03; 16]),
            use_tun: true,
            auth_token: None,
        };
        let encoded = msg.encode();
        let decoded = InitiateSession::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_initiate_encode_decode_with_auth() {
        let msg = InitiateSession {
            initiator: RouterId::from_bytes([0xAA; 32]),
            local_pivot: SessionHopId::new([0xBB; 16]),
            remote_pivot: SessionHopId::new([0xCC; 16]),
            use_tun: false,
            auth_token: Some(b"secret-token-123".to_vec()),
        };
        let encoded = msg.encode();
        let decoded = InitiateSession::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_initiate_truncated() {
        assert!(InitiateSession::decode(&[]).is_err());
        assert!(InitiateSession::decode(&[1, 2]).is_err());
    }

    #[test]
    fn test_close_encode_decode() {
        let msg = CloseSession {
            session_tag: SessionTag::new(42),
            reason: "timeout".to_string(),
        };
        let encoded = msg.encode();
        let decoded = CloseSession::decode(&encoded).expect("close decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_close_empty_reason() {
        let msg = CloseSession {
            session_tag: SessionTag::new(1),
            reason: String::new(),
        };
        let encoded = msg.encode();
        let decoded = CloseSession::decode(&encoded).expect("empty reason");
        assert_eq!(decoded.reason, "");
    }

    #[test]
    fn test_path_switch_encode_decode() {
        let msg = SessionPathSwitch {
            session_tag: SessionTag::new(7),
            local_pivot: SessionHopId::new([0x10; 16]),
            remote_pivot: SessionHopId::new([0x20; 16]),
        };
        let encoded = msg.encode();
        let decoded = SessionPathSwitch::decode(&encoded).expect("path switch decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_path_switch_truncated() {
        assert!(SessionPathSwitch::decode(&[]).is_err());
        assert!(SessionPathSwitch::decode(&[1]).is_err());
    }

    #[test]
    fn test_initiate_constants() {
        assert_eq!(&*initiate::AUTH_ERROR, "!AUTH ERROR");
        assert_eq!(&*initiate::BAD_ROUTE, "!BAD ROUTE");
        assert_eq!(&*initiate::BAD_ADDRESS, "!BAD ADDRESS");
    }
}
