use crate::contact::NodeIdentity;
use thiserror::Error;

use crate::session::{
    AuthenticatedServiceMessage, ServiceMessageError, ServiceMessageKind, SessionHopId, SessionTag,
};

const SESSION_PATH_SWITCH_PAYLOAD_VERSION: u8 = 1;
const SESSION_HOP_ID_LEN: usize = 16;
const SESSION_TAG_LEN: usize = 4;
const SESSION_PATH_SWITCH_PAYLOAD_LEN: usize =
    1 + SESSION_HOP_ID_LEN + SESSION_HOP_ID_LEN + SESSION_TAG_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPathSwitchMessage {
    pub local_pivot: SessionHopId,
    pub remote_pivot: SessionHopId,
    pub session_tag: SessionTag,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSessionPathSwitchMessage {
    message: SessionPathSwitchMessage,
    service_message: AuthenticatedServiceMessage,
}

impl AuthenticatedSessionPathSwitchMessage {
    pub fn sign(
        identity: &NodeIdentity,
        message: SessionPathSwitchMessage,
    ) -> Result<Self, SessionPathSwitchError> {
        let body = encode_session_path_switch_payload(&message);
        let service_message = AuthenticatedServiceMessage::sign(
            identity,
            ServiceMessageKind::LinkSessionPathSwitch,
            body,
        )?;
        Ok(Self {
            message,
            service_message,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, SessionPathSwitchError> {
        self.service_message.encode().map_err(Into::into)
    }

    pub fn decode(input: &[u8]) -> Result<Self, SessionPathSwitchError> {
        Self::decode_verified(input)
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, SessionPathSwitchError> {
        let service_message = AuthenticatedServiceMessage::decode_unverified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, SessionPathSwitchError> {
        let service_message = AuthenticatedServiceMessage::decode_verified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn message(&self) -> &SessionPathSwitchMessage {
        &self.message
    }

    pub fn service_message(&self) -> &AuthenticatedServiceMessage {
        &self.service_message
    }

    pub fn verify(&self) -> Result<(), SessionPathSwitchError> {
        self.service_message.verify()?;
        if self.service_message.kind() != ServiceMessageKind::LinkSessionPathSwitch {
            return Err(SessionPathSwitchError::UnexpectedServiceKind(
                self.service_message.kind(),
            ));
        }

        let encoded = encode_session_path_switch_payload(&self.message);
        if self.service_message.body() != encoded.as_slice() {
            return Err(SessionPathSwitchError::PayloadMismatch);
        }

        Ok(())
    }

    pub(crate) fn from_authenticated_service_message(
        service_message: AuthenticatedServiceMessage,
    ) -> Result<Self, SessionPathSwitchError> {
        if service_message.kind() != ServiceMessageKind::LinkSessionPathSwitch {
            return Err(SessionPathSwitchError::UnexpectedServiceKind(
                service_message.kind(),
            ));
        }

        let message = decode_session_path_switch_payload(service_message.body())?;
        Ok(Self {
            message,
            service_message,
        })
    }
}

#[derive(Debug, Error)]
pub enum SessionPathSwitchError {
    #[error(transparent)]
    ServiceMessage(#[from] ServiceMessageError),
    #[error("session-path-switch payload unsupported version `{0}`")]
    UnsupportedPayloadVersion(u8),
    #[error("session-path-switch payload truncated")]
    PayloadTruncated,
    #[error("session-path-switch payload malformed: {0}")]
    PayloadMalformed(&'static str),
    #[error(
        "session-path-switch lower-level service kind was `{0:?}`, expected LinkSessionPathSwitch"
    )]
    UnexpectedServiceKind(ServiceMessageKind),
    #[error("session-path-switch decoded payload does not match the signed service body")]
    PayloadMismatch,
}

fn encode_session_path_switch_payload(message: &SessionPathSwitchMessage) -> Vec<u8> {
    let mut payload = Vec::with_capacity(SESSION_PATH_SWITCH_PAYLOAD_LEN);
    payload.push(SESSION_PATH_SWITCH_PAYLOAD_VERSION);
    payload.extend_from_slice(message.local_pivot.as_bytes());
    payload.extend_from_slice(message.remote_pivot.as_bytes());
    payload.extend_from_slice(&message.session_tag.get().to_be_bytes());
    payload
}

fn decode_session_path_switch_payload(
    input: &[u8],
) -> Result<SessionPathSwitchMessage, SessionPathSwitchError> {
    let mut cursor = input;
    let version = take_payload_exact(&mut cursor, 1)?[0];
    if version != SESSION_PATH_SWITCH_PAYLOAD_VERSION {
        return Err(SessionPathSwitchError::UnsupportedPayloadVersion(version));
    }

    let local_pivot = SessionHopId::new(
        take_payload_exact(&mut cursor, SESSION_HOP_ID_LEN)?
            .try_into()
            .expect("take_payload_exact guarantees exact byte count"),
    );
    let remote_pivot = SessionHopId::new(
        take_payload_exact(&mut cursor, SESSION_HOP_ID_LEN)?
            .try_into()
            .expect("take_payload_exact guarantees exact byte count"),
    );
    let session_tag = SessionTag::new(u32::from_be_bytes(
        take_payload_exact(&mut cursor, SESSION_TAG_LEN)?
            .try_into()
            .expect("take_payload_exact guarantees exact byte count"),
    ));

    if !cursor.is_empty() {
        return Err(SessionPathSwitchError::PayloadMalformed(
            "unexpected trailing bytes in session-path-switch payload",
        ));
    }

    Ok(SessionPathSwitchMessage {
        local_pivot,
        remote_pivot,
        session_tag,
    })
}

fn take_payload_exact<'a>(
    input: &mut &'a [u8],
    count: usize,
) -> Result<&'a [u8], SessionPathSwitchError> {
    if input.len() < count {
        return Err(SessionPathSwitchError::PayloadTruncated);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}
