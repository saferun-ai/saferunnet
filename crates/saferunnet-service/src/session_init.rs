use saferunnet_crypto::{KeyAlgorithm, PublicKey};
use saferunnet_identity::NodeIdentity;
use thiserror::Error;

use crate::{AuthenticatedServiceMessage, ServiceMessageError, ServiceMessageKind, SessionHopId};

const SESSION_INIT_PAYLOAD_VERSION: u8 = 1;
const SESSION_HOP_ID_LEN: usize = 16;
const SESSION_INIT_BASE_LEN: usize = 1 + 1 + 32 + SESSION_HOP_ID_LEN + SESSION_HOP_ID_LEN + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInitMessage {
    pub initiator: PublicKey,
    pub local_pivot: SessionHopId,
    pub remote_pivot: SessionHopId,
    pub auth_token: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSessionInitMessage {
    message: SessionInitMessage,
    service_message: AuthenticatedServiceMessage,
}

impl AuthenticatedSessionInitMessage {
    pub fn sign(
        identity: &NodeIdentity,
        message: SessionInitMessage,
    ) -> Result<Self, SessionInitError> {
        let body = encode_session_init_payload(&message)?;
        let service_message =
            AuthenticatedServiceMessage::sign(identity, ServiceMessageKind::LinkSessionInit, body)?;
        Ok(Self {
            message,
            service_message,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, SessionInitError> {
        self.service_message.encode().map_err(Into::into)
    }

    pub fn decode(input: &[u8]) -> Result<Self, SessionInitError> {
        Self::decode_verified(input)
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, SessionInitError> {
        let service_message = AuthenticatedServiceMessage::decode_unverified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, SessionInitError> {
        let service_message = AuthenticatedServiceMessage::decode_verified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn message(&self) -> &SessionInitMessage {
        &self.message
    }

    pub fn service_message(&self) -> &AuthenticatedServiceMessage {
        &self.service_message
    }

    pub fn verify(&self) -> Result<(), SessionInitError> {
        self.service_message.verify()?;
        if self.service_message.kind() != ServiceMessageKind::LinkSessionInit {
            return Err(SessionInitError::UnexpectedServiceKind(
                self.service_message.kind(),
            ));
        }

        let encoded = encode_session_init_payload(&self.message)?;
        if self.service_message.body() != encoded.as_slice() {
            return Err(SessionInitError::PayloadMismatch);
        }

        Ok(())
    }

    pub(crate) fn from_authenticated_service_message(
        service_message: AuthenticatedServiceMessage,
    ) -> Result<Self, SessionInitError> {
        if service_message.kind() != ServiceMessageKind::LinkSessionInit {
            return Err(SessionInitError::UnexpectedServiceKind(
                service_message.kind(),
            ));
        }

        let message = decode_session_init_payload(service_message.body())?;
        Ok(Self {
            message,
            service_message,
        })
    }
}

#[derive(Debug, Error)]
pub enum SessionInitError {
    #[error(transparent)]
    ServiceMessage(#[from] ServiceMessageError),
    #[error("session-init payload unsupported version `{0}`")]
    UnsupportedPayloadVersion(u8),
    #[error("session-init payload uses unsupported initiator algorithm id `{0}`")]
    UnsupportedInitiatorAlgorithm(u8),
    #[error("session-init payload truncated")]
    PayloadTruncated,
    #[error("session-init payload malformed: {0}")]
    PayloadMalformed(&'static str),
    #[error("session-init lower-level service kind was `{0:?}`, expected LinkSessionInit")]
    UnexpectedServiceKind(ServiceMessageKind),
    #[error("session-init decoded payload does not match the signed service body")]
    PayloadMismatch,
    #[error("session-init auth token exceeds encoded limit `{max}` with length `{length}` bytes")]
    AuthTokenLengthOverflow { length: usize, max: usize },
}

fn encode_session_init_payload(message: &SessionInitMessage) -> Result<Vec<u8>, SessionInitError> {
    let auth_len = match &message.auth_token {
        Some(auth_token) => Some(u16::try_from(auth_token.len()).map_err(|_| {
            SessionInitError::AuthTokenLengthOverflow {
                length: auth_token.len(),
                max: u16::MAX as usize,
            }
        })?),
        None => None,
    };
    let mut payload = Vec::with_capacity(
        SESSION_INIT_BASE_LEN
            + auth_len
                .map(|length| usize::from(length) + 2)
                .unwrap_or_default(),
    );
    payload.push(SESSION_INIT_PAYLOAD_VERSION);
    payload.push(encode_initiator_algorithm(message.initiator.algorithm()));
    payload.extend_from_slice(&message.initiator.to_bytes());
    payload.extend_from_slice(message.local_pivot.as_bytes());
    payload.extend_from_slice(message.remote_pivot.as_bytes());
    match (&message.auth_token, auth_len) {
        (Some(auth_token), Some(auth_len)) => {
            payload.push(1);
            payload.extend_from_slice(&auth_len.to_be_bytes());
            payload.extend_from_slice(auth_token);
        }
        (None, None) => payload.push(0),
        _ => unreachable!("auth token length is only present when the auth token exists"),
    }
    Ok(payload)
}

fn decode_session_init_payload(input: &[u8]) -> Result<SessionInitMessage, SessionInitError> {
    if input.len() < SESSION_INIT_BASE_LEN {
        return Err(SessionInitError::PayloadTruncated);
    }

    let mut cursor = input;
    let version = take_payload_exact(&mut cursor, 1)?[0];
    if version != SESSION_INIT_PAYLOAD_VERSION {
        return Err(SessionInitError::UnsupportedPayloadVersion(version));
    }

    let algorithm = decode_initiator_algorithm(take_payload_exact(&mut cursor, 1)?[0])?;
    let initiator_bytes: [u8; 32] = take_payload_exact(&mut cursor, 32)?
        .try_into()
        .expect("take_payload_exact guarantees exact byte count");
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

    let auth_token = match take_payload_exact(&mut cursor, 1)?[0] {
        0 => None,
        1 => {
            let auth_len = u16::from_be_bytes(
                take_payload_exact(&mut cursor, 2)?
                    .try_into()
                    .expect("take_payload_exact guarantees exact byte count"),
            ) as usize;
            Some(take_payload_exact(&mut cursor, auth_len)?.to_vec())
        }
        _ => {
            return Err(SessionInitError::PayloadMalformed(
                "unsupported session-init auth-token flag",
            ));
        }
    };

    if !cursor.is_empty() {
        return Err(SessionInitError::PayloadMalformed(
            "unexpected trailing bytes in session-init payload",
        ));
    }

    Ok(SessionInitMessage {
        initiator: PublicKey::from_bytes(algorithm, initiator_bytes),
        local_pivot,
        remote_pivot,
        auth_token,
    })
}

fn encode_initiator_algorithm(algorithm: KeyAlgorithm) -> u8 {
    match algorithm {
        KeyAlgorithm::Ed25519 => 1,
    }
}

fn decode_initiator_algorithm(encoded: u8) -> Result<KeyAlgorithm, SessionInitError> {
    match encoded {
        1 => Ok(KeyAlgorithm::Ed25519),
        _ => Err(SessionInitError::UnsupportedInitiatorAlgorithm(encoded)),
    }
}

fn take_payload_exact<'a>(
    input: &mut &'a [u8],
    count: usize,
) -> Result<&'a [u8], SessionInitError> {
    if input.len() < count {
        return Err(SessionInitError::PayloadTruncated);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}
