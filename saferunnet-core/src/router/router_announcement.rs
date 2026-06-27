use crate::contact::NodeIdentity;
use thiserror::Error;

use crate::{AuthenticatedServiceMessage, ServiceMessageError, ServiceMessageKind};

const ROUTER_PAYLOAD_VERSION: u8 = 1;
const ROUTER_PAYLOAD_HEADER_LEN: usize = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterCapability {
    Relay,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAnnouncement {
    pub sequence: u64,
    pub capabilities: Vec<RouterCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRouterAnnouncement {
    announcement: RouterAnnouncement,
    service_message: AuthenticatedServiceMessage,
}

impl AuthenticatedRouterAnnouncement {
    pub fn sign(
        identity: &NodeIdentity,
        announcement: RouterAnnouncement,
    ) -> Result<Self, RouterAnnouncementError> {
        let body = encode_router_payload(&announcement)?;
        let service_message = AuthenticatedServiceMessage::sign(
            identity,
            ServiceMessageKind::RouterAnnouncement,
            body,
        )?;
        Ok(Self {
            announcement,
            service_message,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, RouterAnnouncementError> {
        self.service_message.encode().map_err(Into::into)
    }

    pub fn decode(input: &[u8]) -> Result<Self, RouterAnnouncementError> {
        Self::decode_verified(input)
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, RouterAnnouncementError> {
        let service_message = AuthenticatedServiceMessage::decode_unverified(input)?;
        Self::from_service_message(service_message)
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, RouterAnnouncementError> {
        let service_message = AuthenticatedServiceMessage::decode_verified(input)?;
        Self::from_service_message(service_message)
    }

    pub fn announcement(&self) -> &RouterAnnouncement {
        &self.announcement
    }

    pub fn service_message(&self) -> &AuthenticatedServiceMessage {
        &self.service_message
    }

    pub fn verify(&self) -> Result<(), RouterAnnouncementError> {
        self.service_message.verify()?;
        if self.service_message.kind() != ServiceMessageKind::RouterAnnouncement {
            return Err(RouterAnnouncementError::UnexpectedServiceKind(
                self.service_message.kind(),
            ));
        }

        let encoded = encode_router_payload(&self.announcement)?;
        if self.service_message.body() != encoded.as_slice() {
            return Err(RouterAnnouncementError::PayloadMismatch);
        }

        Ok(())
    }

    fn from_service_message(
        service_message: AuthenticatedServiceMessage,
    ) -> Result<Self, RouterAnnouncementError> {
        if service_message.kind() != ServiceMessageKind::RouterAnnouncement {
            return Err(RouterAnnouncementError::UnexpectedServiceKind(
                service_message.kind(),
            ));
        }

        let announcement = decode_router_payload(service_message.body())?;
        Ok(Self {
            announcement,
            service_message,
        })
    }
}

#[derive(Debug, Error)]
pub enum RouterAnnouncementError {
    #[error(transparent)]
    ServiceMessage(#[from] ServiceMessageError),
    #[error("router announcement payload unsupported version `{0}`")]
    UnsupportedPayloadVersion(u8),
    #[error("router announcement payload truncated")]
    PayloadTruncated,
    #[error("router announcement payload malformed: {0}")]
    PayloadMalformed(&'static str),
    #[error(
        "router announcement lower-level service kind was `{0:?}`, expected RouterAnnouncement"
    )]
    UnexpectedServiceKind(ServiceMessageKind),
    #[error("router announcement contains duplicate capability `{0:?}`")]
    DuplicateCapability(RouterCapability),
    #[error("router announcement decoded payload does not match the signed service body")]
    PayloadMismatch,
    #[error(
        "router announcement capability count exceeds encoded limit `{max}` with length `{length}`"
    )]
    CapabilityLengthOverflow { length: usize, max: usize },
}

fn encode_router_payload(
    announcement: &RouterAnnouncement,
) -> Result<Vec<u8>, RouterAnnouncementError> {
    validate_capabilities(&announcement.capabilities)?;

    let capability_count = u16::try_from(announcement.capabilities.len()).map_err(|_| {
        RouterAnnouncementError::CapabilityLengthOverflow {
            length: announcement.capabilities.len(),
            max: u16::MAX as usize,
        }
    })?;
    let mut payload =
        Vec::with_capacity(ROUTER_PAYLOAD_HEADER_LEN + announcement.capabilities.len());
    payload.push(ROUTER_PAYLOAD_VERSION);
    payload.extend_from_slice(&announcement.sequence.to_be_bytes());
    payload.extend_from_slice(&capability_count.to_be_bytes());
    for capability in &announcement.capabilities {
        payload.push(encode_capability(*capability));
    }
    Ok(payload)
}

fn decode_router_payload(input: &[u8]) -> Result<RouterAnnouncement, RouterAnnouncementError> {
    if input.len() < ROUTER_PAYLOAD_HEADER_LEN {
        return Err(RouterAnnouncementError::PayloadTruncated);
    }

    let mut cursor = input;
    let version = take_payload_exact(&mut cursor, 1)?[0];
    if version != ROUTER_PAYLOAD_VERSION {
        return Err(RouterAnnouncementError::UnsupportedPayloadVersion(version));
    }

    let sequence = u64::from_be_bytes(
        take_payload_exact(&mut cursor, 8)?
            .try_into()
            .expect("take_payload_exact guarantees exact byte count"),
    );
    let capability_count = u16::from_be_bytes(
        take_payload_exact(&mut cursor, 2)?
            .try_into()
            .expect("take_payload_exact guarantees exact byte count"),
    ) as usize;

    let mut capabilities = Vec::with_capacity(capability_count);
    for _ in 0..capability_count {
        let capability = decode_capability(take_payload_exact(&mut cursor, 1)?[0])?;
        if capabilities.contains(&capability) {
            return Err(RouterAnnouncementError::DuplicateCapability(capability));
        }
        capabilities.push(capability);
    }

    if !cursor.is_empty() {
        return Err(RouterAnnouncementError::PayloadMalformed(
            "unexpected trailing bytes in router announcement payload",
        ));
    }

    Ok(RouterAnnouncement {
        sequence,
        capabilities,
    })
}

fn validate_capabilities(capabilities: &[RouterCapability]) -> Result<(), RouterAnnouncementError> {
    let mut seen = Vec::with_capacity(capabilities.len());
    for capability in capabilities {
        if seen.contains(capability) {
            return Err(RouterAnnouncementError::DuplicateCapability(*capability));
        }
        seen.push(*capability);
    }
    Ok(())
}

fn encode_capability(capability: RouterCapability) -> u8 {
    match capability {
        RouterCapability::Relay => 1,
        RouterCapability::Exit => 2,
    }
}

fn decode_capability(encoded: u8) -> Result<RouterCapability, RouterAnnouncementError> {
    match encoded {
        1 => Ok(RouterCapability::Relay),
        2 => Ok(RouterCapability::Exit),
        _ => Err(RouterAnnouncementError::PayloadMalformed(
            "unsupported router capability id",
        )),
    }
}

fn take_payload_exact<'a>(
    input: &mut &'a [u8],
    count: usize,
) -> Result<&'a [u8], RouterAnnouncementError> {
    if input.len() < count {
        return Err(RouterAnnouncementError::PayloadTruncated);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}
