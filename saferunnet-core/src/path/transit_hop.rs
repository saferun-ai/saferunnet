use crate::contact::NodeIdentity;
use thiserror::Error;

use crate::{AuthenticatedServiceMessage, ServiceMessageError, ServiceMessageKind};

pub const MAX_TRANSIT_PAYLOAD: usize = 1024;
const TRANSIT_HOP_VERSION: u8 = 1;
const TRANSIT_HOP_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitHopMessage {
    pub path_id: u64,
    pub hop_index: u8,
    pub encrypted_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedTransitHopMessage {
    message: TransitHopMessage,
    service_message: AuthenticatedServiceMessage,
}

impl AuthenticatedTransitHopMessage {
    pub fn sign(
        identity: &NodeIdentity,
        message: TransitHopMessage,
    ) -> Result<Self, TransitHopError> {
        if message.encrypted_payload.len() > MAX_TRANSIT_PAYLOAD {
            return Err(TransitHopError::PayloadTooLarge {
                max: MAX_TRANSIT_PAYLOAD,
                found: message.encrypted_payload.len(),
            });
        }
        let body = encode_transit_hop_payload(&message);
        let service_message =
            AuthenticatedServiceMessage::sign(identity, ServiceMessageKind::LinkTransitHop, body)?;
        Ok(Self {
            message,
            service_message,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, TransitHopError> {
        self.service_message.encode().map_err(Into::into)
    }

    pub fn decode(input: &[u8]) -> Result<Self, TransitHopError> {
        Self::decode_verified(input)
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, TransitHopError> {
        let service_message = AuthenticatedServiceMessage::decode_unverified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, TransitHopError> {
        let service_message = AuthenticatedServiceMessage::decode_verified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn message(&self) -> &TransitHopMessage {
        &self.message
    }

    pub fn service_message(&self) -> &AuthenticatedServiceMessage {
        &self.service_message
    }

    pub fn verify(&self) -> Result<(), TransitHopError> {
        self.service_message.verify()?;
        if self.service_message.kind() != ServiceMessageKind::LinkTransitHop {
            return Err(TransitHopError::UnexpectedServiceKind(
                self.service_message.kind(),
            ));
        }

        let encoded = encode_transit_hop_payload(&self.message);
        if self.service_message.body() != encoded.as_slice() {
            return Err(TransitHopError::PayloadMismatch);
        }

        Ok(())
    }

    pub(crate) fn from_authenticated_service_message(
        service_message: AuthenticatedServiceMessage,
    ) -> Result<Self, TransitHopError> {
        if service_message.kind() != ServiceMessageKind::LinkTransitHop {
            return Err(TransitHopError::UnexpectedServiceKind(
                service_message.kind(),
            ));
        }

        let message = decode_transit_hop_payload(service_message.body())?;
        Ok(Self {
            message,
            service_message,
        })
    }
}

#[derive(Debug, Error)]
pub enum TransitHopError {
    #[error(transparent)]
    ServiceMessage(#[from] ServiceMessageError),
    #[error("transit payload exceeds maximum of {max}")]
    PayloadTooLarge { max: usize, found: usize },
    #[error("unsupported transit hop version `{0}`")]
    UnsupportedVersion(u8),
    #[error("transit hop payload truncated")]
    PayloadTruncated,
    #[error("transit hop payload malformed: {0}")]
    PayloadMalformed(&'static str),
    #[error("transit hop lower-level service kind was `{0:?}`, expected LinkTransitHop")]
    UnexpectedServiceKind(ServiceMessageKind),
    #[error("transit hop decoded payload does not match the signed service body")]
    PayloadMismatch,
    #[error(
        "transit hop declared payload length {declared} does not match remaining data length {remaining}"
    )]
    PayloadLengthMismatch { declared: u16, remaining: usize },
}

fn encode_transit_hop_payload(message: &TransitHopMessage) -> Vec<u8> {
    let payload_len = message.encrypted_payload.len() as u16;
    let mut payload = Vec::with_capacity(TRANSIT_HOP_HEADER_LEN + message.encrypted_payload.len());
    payload.push(TRANSIT_HOP_VERSION);
    payload.extend_from_slice(&message.path_id.to_be_bytes());
    payload.push(message.hop_index);
    payload.extend_from_slice(&payload_len.to_be_bytes());
    payload.extend_from_slice(&message.encrypted_payload);
    payload
}

fn decode_transit_hop_payload(input: &[u8]) -> Result<TransitHopMessage, TransitHopError> {
    if input.len() < TRANSIT_HOP_HEADER_LEN {
        return Err(TransitHopError::PayloadTruncated);
    }

    let mut cursor = input;
    let version = take_payload_exact(&mut cursor, 1)?[0];
    if version != TRANSIT_HOP_VERSION {
        return Err(TransitHopError::UnsupportedVersion(version));
    }

    let path_id = u64::from_be_bytes(
        take_payload_exact(&mut cursor, 8)?
            .try_into()
            .expect("take_payload_exact guarantees exact byte count"),
    );

    let hop_index = take_payload_exact(&mut cursor, 1)?[0];

    let payload_len = u16::from_be_bytes(
        take_payload_exact(&mut cursor, 2)?
            .try_into()
            .expect("take_payload_exact guarantees exact byte count"),
    );

    if payload_len as usize > MAX_TRANSIT_PAYLOAD {
        return Err(TransitHopError::PayloadTooLarge {
            max: MAX_TRANSIT_PAYLOAD,
            found: payload_len as usize,
        });
    }

    if cursor.len() < payload_len as usize {
        return Err(TransitHopError::PayloadLengthMismatch {
            declared: payload_len,
            remaining: cursor.len(),
        });
    }

    let encrypted_payload = take_payload_exact(&mut cursor, payload_len as usize)?.to_vec();

    if !cursor.is_empty() {
        return Err(TransitHopError::PayloadMalformed(
            "unexpected trailing bytes in transit hop payload",
        ));
    }

    Ok(TransitHopMessage {
        path_id,
        hop_index,
        encrypted_payload,
    })
}

fn take_payload_exact<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], TransitHopError> {
    if input.len() < count {
        return Err(TransitHopError::PayloadTruncated);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}
