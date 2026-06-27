use crate::contact::NodeIdentity;
use saferunnet_crypto::{KeyAlgorithm, PublicKey};
use thiserror::Error;

use crate::{AuthenticatedServiceMessage, ServiceMessageError, ServiceMessageKind};

pub const MAX_DHT_INTRO_ENTRIES: usize = 8;
const DHT_INTRO_VERSION: u8 = 1;
const DHT_INTRO_HEADER_LEN: usize = 2;
const DHT_INTRO_ENTRY_LEN: usize = 35;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Ipv4 = 1,
    Ipv6 = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtIntroEntry {
    pub public_key: PublicKey,
    pub family: AddressFamily,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtIntroMessage {
    pub entries: Vec<DhtIntroEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedDhtIntroMessage {
    payload: DhtIntroMessage,
    service_message: AuthenticatedServiceMessage,
}

impl AuthenticatedDhtIntroMessage {
    pub fn sign(identity: &NodeIdentity, payload: DhtIntroMessage) -> Result<Self, DhtIntroError> {
        let body = encode_dht_intro_payload(&payload)?;
        let service_message =
            AuthenticatedServiceMessage::sign(identity, ServiceMessageKind::DhtIntro, body)?;
        Ok(Self {
            payload,
            service_message,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, DhtIntroError> {
        self.service_message.encode().map_err(Into::into)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DhtIntroError> {
        Self::decode_verified(input)
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, DhtIntroError> {
        let service_message = AuthenticatedServiceMessage::decode_unverified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, DhtIntroError> {
        let service_message = AuthenticatedServiceMessage::decode_verified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn payload(&self) -> &DhtIntroMessage {
        &self.payload
    }

    pub fn service_message(&self) -> &AuthenticatedServiceMessage {
        &self.service_message
    }

    pub fn verify(&self) -> Result<(), DhtIntroError> {
        self.service_message.verify()?;
        if self.service_message.kind() != ServiceMessageKind::DhtIntro {
            return Err(DhtIntroError::Service(ServiceMessageError::FrameMalformed(
                "dht intro lower-level service kind mismatch",
            )));
        }

        let encoded = encode_dht_intro_payload(&self.payload)?;
        if self.service_message.body() != encoded.as_slice() {
            return Err(DhtIntroError::Service(ServiceMessageError::FrameMalformed(
                "dht intro decoded payload does not match the signed service body",
            )));
        }

        Ok(())
    }

    pub(crate) fn from_authenticated_service_message(
        service_message: AuthenticatedServiceMessage,
    ) -> Result<Self, DhtIntroError> {
        if service_message.kind() != ServiceMessageKind::DhtIntro {
            return Err(DhtIntroError::Service(ServiceMessageError::FrameMalformed(
                "dht intro lower-level service kind mismatch",
            )));
        }

        let payload = decode_dht_intro_payload(service_message.body())?;
        Ok(Self {
            payload,
            service_message,
        })
    }
}

#[derive(Debug, Error)]
pub enum DhtIntroError {
    #[error("dht intro must contain at least one entry")]
    Empty,
    #[error("dht intro entries exceed maximum of {max}")]
    TooMany { max: usize, found: usize },
    #[error("unsupported dht intro payload version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported dht intro address family byte {0}")]
    UnsupportedAddressFamily(u8),
    #[error("dht intro payload truncated")]
    PayloadTruncated,
    #[error("dht intro payload malformed: {0}")]
    PayloadMalformed(&'static str),
    #[error("{0}")]
    Service(#[from] ServiceMessageError),
}

// Encode helpers

fn encode_dht_intro_payload(message: &DhtIntroMessage) -> Result<Vec<u8>, DhtIntroError> {
    let count = message.entries.len();
    if count == 0 {
        return Err(DhtIntroError::Empty);
    }
    if count > MAX_DHT_INTRO_ENTRIES {
        return Err(DhtIntroError::TooMany {
            max: MAX_DHT_INTRO_ENTRIES,
            found: count,
        });
    }

    let mut payload = Vec::with_capacity(DHT_INTRO_HEADER_LEN + count * DHT_INTRO_ENTRY_LEN);
    payload.push(DHT_INTRO_VERSION);
    payload.push(count as u8);
    for entry in &message.entries {
        payload.extend_from_slice(&entry.public_key.to_bytes());
        payload.push(encode_address_family(entry.family));
        payload.extend_from_slice(&entry.port.to_be_bytes());
    }
    Ok(payload)
}

fn decode_dht_intro_payload(input: &[u8]) -> Result<DhtIntroMessage, DhtIntroError> {
    let mut cursor = input;

    let version = take_payload_exact(&mut cursor, 1)?[0];
    if version != DHT_INTRO_VERSION {
        return Err(DhtIntroError::UnsupportedVersion(version));
    }

    let count = take_payload_exact(&mut cursor, 1)?[0] as usize;
    if count == 0 {
        return Err(DhtIntroError::Empty);
    }
    if count > MAX_DHT_INTRO_ENTRIES {
        return Err(DhtIntroError::TooMany {
            max: MAX_DHT_INTRO_ENTRIES,
            found: count,
        });
    }

    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let pk_bytes = take_payload_exact(&mut cursor, 32)?;
        let public_key = PublicKey::from_bytes(
            KeyAlgorithm::Ed25519,
            pk_bytes
                .try_into()
                .expect("take_payload_exact guarantees exact byte count"),
        );

        let family_byte = take_payload_exact(&mut cursor, 1)?[0];
        let family = decode_address_family(family_byte)?;

        let port = u16::from_be_bytes(
            take_payload_exact(&mut cursor, 2)?
                .try_into()
                .expect("take_payload_exact guarantees exact byte count"),
        );

        entries.push(DhtIntroEntry {
            public_key,
            family,
            port,
        });
    }

    if !cursor.is_empty() {
        return Err(DhtIntroError::PayloadMalformed(
            "unexpected trailing bytes in dht intro payload",
        ));
    }

    Ok(DhtIntroMessage { entries })
}

fn encode_address_family(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::Ipv4 => 1,
        AddressFamily::Ipv6 => 2,
    }
}

fn decode_address_family(encoded: u8) -> Result<AddressFamily, DhtIntroError> {
    match encoded {
        1 => Ok(AddressFamily::Ipv4),
        2 => Ok(AddressFamily::Ipv6),
        _ => Err(DhtIntroError::UnsupportedAddressFamily(encoded)),
    }
}

fn take_payload_exact<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], DhtIntroError> {
    if input.len() < count {
        return Err(DhtIntroError::PayloadTruncated);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}
