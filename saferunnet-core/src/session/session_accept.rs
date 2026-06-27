use crate::contact::NodeIdentity;
use thiserror::Error;

use crate::session::{AuthenticatedServiceMessage, ServiceMessageError, ServiceMessageKind, SessionTag};

const SESSION_ACCEPT_PAYLOAD_VERSION: u8 = 1;
const SESSION_ACCEPT_PAYLOAD_LEN: usize = 1 + 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAcceptMessage {
    pub session_tag: SessionTag,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSessionAcceptMessage {
    message: SessionAcceptMessage,
    service_message: AuthenticatedServiceMessage,
}

impl AuthenticatedSessionAcceptMessage {
    pub fn sign(
        identity: &NodeIdentity,
        message: SessionAcceptMessage,
    ) -> Result<Self, SessionAcceptError> {
        let body = encode_session_accept_payload(&message);
        let service_message = AuthenticatedServiceMessage::sign(
            identity,
            ServiceMessageKind::LinkSessionAccept,
            body,
        )?;
        Ok(Self {
            message,
            service_message,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, SessionAcceptError> {
        self.service_message.encode().map_err(Into::into)
    }

    pub fn decode(input: &[u8]) -> Result<Self, SessionAcceptError> {
        Self::decode_verified(input)
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, SessionAcceptError> {
        let service_message = AuthenticatedServiceMessage::decode_unverified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, SessionAcceptError> {
        let service_message = AuthenticatedServiceMessage::decode_verified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn message(&self) -> &SessionAcceptMessage {
        &self.message
    }

    pub fn service_message(&self) -> &AuthenticatedServiceMessage {
        &self.service_message
    }

    pub fn verify(&self) -> Result<(), SessionAcceptError> {
        self.service_message.verify()?;
        if self.service_message.kind() != ServiceMessageKind::LinkSessionAccept {
            return Err(SessionAcceptError::UnexpectedServiceKind(
                self.service_message.kind(),
            ));
        }

        let encoded = encode_session_accept_payload(&self.message);
        if self.service_message.body() != encoded.as_slice() {
            return Err(SessionAcceptError::PayloadMismatch);
        }

        Ok(())
    }

    pub(crate) fn from_authenticated_service_message(
        service_message: AuthenticatedServiceMessage,
    ) -> Result<Self, SessionAcceptError> {
        if service_message.kind() != ServiceMessageKind::LinkSessionAccept {
            return Err(SessionAcceptError::UnexpectedServiceKind(
                service_message.kind(),
            ));
        }

        let message = decode_session_accept_payload(service_message.body())?;
        Ok(Self {
            message,
            service_message,
        })
    }
}

#[derive(Debug, Error)]
pub enum SessionAcceptError {
    #[error(transparent)]
    ServiceMessage(#[from] ServiceMessageError),
    #[error("session-accept payload unsupported version `{0}`")]
    UnsupportedPayloadVersion(u8),
    #[error("session-accept payload truncated")]
    PayloadTruncated,
    #[error("session-accept payload malformed: {0}")]
    PayloadMalformed(&'static str),
    #[error("session-accept lower-level service kind was `{0:?}`, expected LinkSessionAccept")]
    UnexpectedServiceKind(ServiceMessageKind),
    #[error("session-accept decoded payload does not match the signed service body")]
    PayloadMismatch,
}

fn encode_session_accept_payload(message: &SessionAcceptMessage) -> Vec<u8> {
    let mut payload = Vec::with_capacity(SESSION_ACCEPT_PAYLOAD_LEN);
    payload.push(SESSION_ACCEPT_PAYLOAD_VERSION);
    payload.extend_from_slice(&message.session_tag.get().to_be_bytes());
    payload
}

fn decode_session_accept_payload(input: &[u8]) -> Result<SessionAcceptMessage, SessionAcceptError> {
    let mut cursor = input;
    let version = take_payload_exact(&mut cursor, 1)?[0];
    if version != SESSION_ACCEPT_PAYLOAD_VERSION {
        return Err(SessionAcceptError::UnsupportedPayloadVersion(version));
    }

    let session_tag = SessionTag::new(u32::from_be_bytes(
        take_payload_exact(&mut cursor, 4)?
            .try_into()
            .expect("take_payload_exact guarantees exact byte count"),
    ));

    if !cursor.is_empty() {
        return Err(SessionAcceptError::PayloadMalformed(
            "unexpected trailing bytes in session-accept payload",
        ));
    }

    Ok(SessionAcceptMessage { session_tag })
}

fn take_payload_exact<'a>(
    input: &mut &'a [u8],
    count: usize,
) -> Result<&'a [u8], SessionAcceptError> {
    if input.len() < count {
        return Err(SessionAcceptError::PayloadTruncated);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}
