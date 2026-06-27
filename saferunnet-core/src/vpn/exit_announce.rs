use crate::contact::NodeIdentity;
use saferunnet_crypto::PublicKey;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitAnnounceMessage {
    pub exit_public_key: PublicKey,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedExitAnnounceMessage {
    inner: crate::AuthenticatedServiceMessage,
    payload: ExitAnnounceMessage,
}

#[derive(Debug, Error)]
pub enum ExitAnnounceError {
    #[error("no addresses provided")]
    EmptyAddresses,
    #[error(transparent)]
    Service(#[from] crate::ServiceMessageError),
    #[error("wrong message kind: expected ExitAnnounce")]
    WrongKind,
}

impl AuthenticatedExitAnnounceMessage {
    pub fn sign(
        identity: &NodeIdentity,
        exit_public_key: PublicKey,
        addresses: Vec<String>,
    ) -> Result<Self, ExitAnnounceError> {
        if addresses.is_empty() {
            return Err(ExitAnnounceError::EmptyAddresses);
        }
        let payload = ExitAnnounceMessage {
            exit_public_key: exit_public_key.clone(),
            addresses,
        };
        let body = encode_exit_announce_payload(&payload);
        let inner = crate::AuthenticatedServiceMessage::sign(
            identity,
            crate::ServiceMessageKind::ExitAnnounce,
            body,
        )?;
        Ok(Self { inner, payload })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ExitAnnounceError> {
        Ok(self.inner.encode()?)
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, ExitAnnounceError> {
        let inner = crate::AuthenticatedServiceMessage::decode_verified(input)?;
        if inner.kind() != crate::ServiceMessageKind::ExitAnnounce {
            return Err(ExitAnnounceError::WrongKind);
        }
        let payload = decode_exit_announce_payload(inner.body())?;
        Ok(Self { inner, payload })
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, ExitAnnounceError> {
        let inner = crate::AuthenticatedServiceMessage::decode_unverified(input)?;
        if inner.kind() != crate::ServiceMessageKind::ExitAnnounce {
            return Err(ExitAnnounceError::WrongKind);
        }
        let payload = decode_exit_announce_payload(inner.body())?;
        Ok(Self { inner, payload })
    }

    pub fn exit_public_key(&self) -> &PublicKey {
        &self.payload.exit_public_key
    }

    pub fn addresses(&self) -> &[String] {
        &self.payload.addresses
    }
}

fn encode_exit_announce_payload(msg: &ExitAnnounceMessage) -> Vec<u8> {
    let pk_bytes = msg.exit_public_key.to_bytes();
    let addr_count = msg.addresses.len() as u8;
    let mut body = Vec::with_capacity(1 + pk_bytes.len() + 1);
    body.push(addr_count);
    body.extend_from_slice(&pk_bytes);
    for addr in &msg.addresses {
        body.push(addr.len() as u8);
        body.extend_from_slice(addr.as_bytes());
    }
    body
}

fn decode_exit_announce_payload(input: &[u8]) -> Result<ExitAnnounceMessage, ExitAnnounceError> {
    if input.is_empty() {
        return Err(ExitAnnounceError::EmptyAddresses);
    }
    let addr_count = input[0] as usize;
    if addr_count == 0 {
        return Err(ExitAnnounceError::EmptyAddresses);
    }
    let pk_bytes_len = 32;
    if input.len() < 1 + pk_bytes_len {
        return Err(ExitAnnounceError::Service(
            crate::ServiceMessageError::FrameTruncated,
        ));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&input[1..1 + pk_bytes_len]);
    let exit_public_key = PublicKey::from_bytes(saferunnet_crypto::KeyAlgorithm::Ed25519, pk_arr);
    let mut addresses = Vec::with_capacity(addr_count);
    let mut cursor = 1 + pk_bytes_len;
    for _ in 0..addr_count {
        if cursor >= input.len() {
            return Err(ExitAnnounceError::Service(
                crate::ServiceMessageError::FrameTruncated,
            ));
        }
        let len = input[cursor] as usize;
        cursor += 1;
        if cursor + len > input.len() {
            return Err(ExitAnnounceError::Service(
                crate::ServiceMessageError::FrameTruncated,
            ));
        }
        addresses.push(String::from_utf8_lossy(&input[cursor..cursor + len]).into_owned());
        cursor += len;
    }
    Ok(ExitAnnounceMessage {
        exit_public_key,
        addresses,
    })
}
