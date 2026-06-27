use crate::contact::NodeIdentity;
use thiserror::Error;

use crate::session::{AuthenticatedServiceMessage, ServiceMessageError, ServiceMessageKind, SessionTag};

const SESSION_CLOSE_PAYLOAD_VERSION: u8 = 1;
const SESSION_CLOSE_PAYLOAD_LEN: usize = 1 + 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCloseMessage {
    pub session_tag: SessionTag,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSessionCloseMessage {
    message: SessionCloseMessage,
    service_message: AuthenticatedServiceMessage,
}

impl AuthenticatedSessionCloseMessage {
    pub fn sign(
        identity: &NodeIdentity,
        message: SessionCloseMessage,
    ) -> Result<Self, SessionCloseError> {
        let body = encode_session_close_payload(&message);
        let service_message = AuthenticatedServiceMessage::sign(
            identity,
            ServiceMessageKind::LinkSessionClose,
            body,
        )?;
        Ok(Self {
            message,
            service_message,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, SessionCloseError> {
        self.service_message.encode().map_err(Into::into)
    }

    pub fn decode(input: &[u8]) -> Result<Self, SessionCloseError> {
        Self::decode_verified(input)
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, SessionCloseError> {
        let service_message = AuthenticatedServiceMessage::decode_unverified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, SessionCloseError> {
        let service_message = AuthenticatedServiceMessage::decode_verified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn message(&self) -> &SessionCloseMessage {
        &self.message
    }

    pub fn service_message(&self) -> &AuthenticatedServiceMessage {
        &self.service_message
    }

    pub fn verify(&self) -> Result<(), SessionCloseError> {
        self.service_message.verify()?;
        if self.service_message.kind() != ServiceMessageKind::LinkSessionClose {
            return Err(SessionCloseError::UnexpectedServiceKind(
                self.service_message.kind(),
            ));
        }

        let encoded = encode_session_close_payload(&self.message);
        if self.service_message.body() != encoded.as_slice() {
            return Err(SessionCloseError::PayloadMismatch);
        }

        Ok(())
    }

    pub(crate) fn from_authenticated_service_message(
        service_message: AuthenticatedServiceMessage,
    ) -> Result<Self, SessionCloseError> {
        if service_message.kind() != ServiceMessageKind::LinkSessionClose {
            return Err(SessionCloseError::UnexpectedServiceKind(
                service_message.kind(),
            ));
        }

        let message = decode_session_close_payload(service_message.body())?;
        Ok(Self {
            message,
            service_message,
        })
    }
}

#[derive(Debug, Error)]
pub enum SessionCloseError {
    #[error(transparent)]
    ServiceMessage(#[from] ServiceMessageError),
    #[error("session-close payload unsupported version `{0}`")]
    UnsupportedPayloadVersion(u8),
    #[error("session-close payload truncated")]
    PayloadTruncated,
    #[error("session-close payload malformed: {0}")]
    PayloadMalformed(&'static str),
    #[error("session-close lower-level service kind was `{0:?}`, expected LinkSessionClose")]
    UnexpectedServiceKind(ServiceMessageKind),
    #[error("session-close decoded payload does not match the signed service body")]
    PayloadMismatch,
}

fn encode_session_close_payload(message: &SessionCloseMessage) -> Vec<u8> {
    let mut payload = Vec::with_capacity(SESSION_CLOSE_PAYLOAD_LEN);
    payload.push(SESSION_CLOSE_PAYLOAD_VERSION);
    payload.extend_from_slice(&message.session_tag.get().to_be_bytes());
    payload
}

fn decode_session_close_payload(input: &[u8]) -> Result<SessionCloseMessage, SessionCloseError> {
    let mut cursor = input;
    let version = take_payload_exact(&mut cursor, 1)?[0];
    if version != SESSION_CLOSE_PAYLOAD_VERSION {
        return Err(SessionCloseError::UnsupportedPayloadVersion(version));
    }

    let session_tag = SessionTag::new(u32::from_be_bytes(
        take_payload_exact(&mut cursor, 4)?
            .try_into()
            .expect("take_payload_exact guarantees exact byte count"),
    ));

    if !cursor.is_empty() {
        return Err(SessionCloseError::PayloadMalformed(
            "unexpected trailing bytes in session-close payload",
        ));
    }

    Ok(SessionCloseMessage { session_tag })
}

fn take_payload_exact<'a>(
    input: &mut &'a [u8],
    count: usize,
) -> Result<&'a [u8], SessionCloseError> {
    if input.len() < count {
        return Err(SessionCloseError::PayloadTruncated);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}
