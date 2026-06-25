use saferunnet_identity::NodeIdentity;
use thiserror::Error;

use crate::{AuthenticatedServiceMessage, ServiceMessageError, ServiceMessageKind};

const PATH_CONTROL_PAYLOAD_VERSION: u8 = 1;
const PATH_CONTROL_PING_VARIANT_ID: u8 = 1;
const PATH_CONTROL_PING_REQUEST_ID_LEN: usize = 8;
const PATH_CONTROL_PING_PAYLOAD_LEN: usize = 2 + PATH_CONTROL_PING_REQUEST_ID_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathControlMessage {
    Ping(PathPing),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPing {
    pub request_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPathControlMessage {
    message: PathControlMessage,
    service_message: AuthenticatedServiceMessage,
}

impl AuthenticatedPathControlMessage {
    pub fn sign(
        identity: &NodeIdentity,
        message: PathControlMessage,
    ) -> Result<Self, PathControlError> {
        let body = encode_path_control_payload(&message);
        let service_message =
            AuthenticatedServiceMessage::sign(identity, ServiceMessageKind::LinkPathControl, body)?;
        Ok(Self {
            message,
            service_message,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PathControlError> {
        self.service_message.encode().map_err(Into::into)
    }

    pub fn decode(input: &[u8]) -> Result<Self, PathControlError> {
        Self::decode_verified(input)
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, PathControlError> {
        let service_message = AuthenticatedServiceMessage::decode_unverified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, PathControlError> {
        let service_message = AuthenticatedServiceMessage::decode_verified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn message(&self) -> &PathControlMessage {
        &self.message
    }

    pub fn service_message(&self) -> &AuthenticatedServiceMessage {
        &self.service_message
    }

    pub fn verify(&self) -> Result<(), PathControlError> {
        self.service_message.verify()?;
        if self.service_message.kind() != ServiceMessageKind::LinkPathControl {
            return Err(PathControlError::UnexpectedServiceKind(
                self.service_message.kind(),
            ));
        }

        let encoded = encode_path_control_payload(&self.message);
        if self.service_message.body() != encoded.as_slice() {
            return Err(PathControlError::PayloadMismatch);
        }

        Ok(())
    }

    pub(crate) fn from_authenticated_service_message(
        service_message: AuthenticatedServiceMessage,
    ) -> Result<Self, PathControlError> {
        if service_message.kind() != ServiceMessageKind::LinkPathControl {
            return Err(PathControlError::UnexpectedServiceKind(
                service_message.kind(),
            ));
        }

        let message = decode_path_control_payload(service_message.body())?;
        Ok(Self {
            message,
            service_message,
        })
    }
}

#[derive(Debug, Error)]
pub enum PathControlError {
    #[error(transparent)]
    ServiceMessage(#[from] ServiceMessageError),
    #[error("path control payload unsupported version `{0}`")]
    UnsupportedPayloadVersion(u8),
    #[error("path control payload truncated")]
    PayloadTruncated,
    #[error("path control payload malformed: {0}")]
    PayloadMalformed(&'static str),
    #[error("path control lower-level service kind was `{0:?}`, expected LinkPathControl")]
    UnexpectedServiceKind(ServiceMessageKind),
    #[error("path control decoded payload does not match the signed service body")]
    PayloadMismatch,
}

fn encode_path_control_payload(message: &PathControlMessage) -> Vec<u8> {
    match message {
        PathControlMessage::Ping(ping) => {
            let mut payload = Vec::with_capacity(PATH_CONTROL_PING_PAYLOAD_LEN);
            payload.push(PATH_CONTROL_PAYLOAD_VERSION);
            payload.push(PATH_CONTROL_PING_VARIANT_ID);
            payload.extend_from_slice(&ping.request_id.to_be_bytes());
            payload
        }
    }
}

fn decode_path_control_payload(input: &[u8]) -> Result<PathControlMessage, PathControlError> {
    let mut cursor = input;
    let version = take_payload_exact(&mut cursor, 1)?[0];
    if version != PATH_CONTROL_PAYLOAD_VERSION {
        return Err(PathControlError::UnsupportedPayloadVersion(version));
    }

    let variant = take_payload_exact(&mut cursor, 1)?[0];
    match variant {
        PATH_CONTROL_PING_VARIANT_ID => decode_path_ping_payload(cursor),
        _ => Err(PathControlError::PayloadMalformed(
            "unsupported path control variant id",
        )),
    }
}

fn decode_path_ping_payload(input: &[u8]) -> Result<PathControlMessage, PathControlError> {
    let mut cursor = input;
    let request_id = u64::from_be_bytes(
        take_payload_exact(&mut cursor, PATH_CONTROL_PING_REQUEST_ID_LEN)?
            .try_into()
            .expect("take_payload_exact guarantees exact byte count"),
    );

    if !cursor.is_empty() {
        return Err(PathControlError::PayloadMalformed(
            "unexpected trailing bytes in path control payload",
        ));
    }

    Ok(PathControlMessage::Ping(PathPing { request_id }))
}

fn take_payload_exact<'a>(
    input: &mut &'a [u8],
    count: usize,
) -> Result<&'a [u8], PathControlError> {
    if input.len() < count {
        return Err(PathControlError::PayloadTruncated);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}
