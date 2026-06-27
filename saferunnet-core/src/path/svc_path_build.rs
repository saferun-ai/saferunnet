use crate::contact::NodeIdentity;
use saferunnet_crypto::{KeyAlgorithm, PublicKey};
use thiserror::Error;

use crate::{AuthenticatedServiceMessage, ServiceMessageError, ServiceMessageKind};

pub const MAX_PATH_HOPS: usize = 8;
const PATH_BUILD_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathHop {
    pub router_id: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathBuildMessage {
    pub path_id: u64,
    pub hops: Vec<PathHop>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathBuildResponse {
    pub path_id: u64,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPathBuildMessage {
    inner: AuthenticatedServiceMessage,
    payload: PathBuildMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPathBuildResponse {
    inner: AuthenticatedServiceMessage,
    payload: PathBuildResponse,
}

#[derive(Debug, Error)]
pub enum PathBuildError {
    #[error("path build payload truncated")]
    PayloadTruncated,
    #[error("path build payload malformed: {0}")]
    PayloadMalformed(&'static str),
    #[error("unsupported path build payload version {0}")]
    UnsupportedPayloadVersion(u8),
    #[error("unexpected service message kind")]
    UnexpectedServiceKind,
    #[error("unexpected response service message kind")]
    UnexpectedResponseServiceKind,
    #[error("{0}")]
    Service(#[from] ServiceMessageError),
}

impl PathBuildMessage {
    pub fn encode(&self) -> Result<Vec<u8>, PathBuildError> {
        if self.hops.is_empty() {
            return Err(PathBuildError::PayloadMalformed("empty hops"));
        }
        if self.hops.len() > MAX_PATH_HOPS {
            return Err(PathBuildError::PayloadMalformed(
                "hops exceed MAX_PATH_HOPS",
            ));
        }
        let mut buf = Vec::with_capacity(2 + 8 + self.hops.len() * 32);
        buf.push(PATH_BUILD_VERSION);
        buf.push(self.hops.len() as u8);
        buf.extend_from_slice(&self.path_id.to_be_bytes());
        for hop in &self.hops {
            buf.extend_from_slice(&hop.router_id.to_bytes());
        }
        Ok(buf)
    }

    pub fn decode(input: &[u8]) -> Result<Self, PathBuildError> {
        if input.len() < 10 {
            return Err(PathBuildError::PayloadTruncated);
        }
        let version = input[0];
        if version != PATH_BUILD_VERSION {
            return Err(PathBuildError::UnsupportedPayloadVersion(version));
        }
        let hop_count = input[1] as usize;
        if hop_count == 0 {
            return Err(PathBuildError::PayloadMalformed("empty hops"));
        }
        if hop_count > MAX_PATH_HOPS {
            return Err(PathBuildError::PayloadMalformed(
                "hops exceed MAX_PATH_HOPS",
            ));
        }
        let expected = 2 + 8 + hop_count * 32;
        if input.len() < expected {
            return Err(PathBuildError::PayloadTruncated);
        }
        if input.len() > expected {
            return Err(PathBuildError::PayloadMalformed(
                "unexpected trailing bytes",
            ));
        }
        let path_id = u64::from_be_bytes(input[2..10].try_into().unwrap());
        let mut hops = Vec::with_capacity(hop_count);
        let mut offset = 10;
        for _ in 0..hop_count {
            let key_bytes: [u8; 32] = input[offset..offset + 32].try_into().unwrap();
            let router_id = PublicKey::from_bytes(KeyAlgorithm::Ed25519, key_bytes);
            hops.push(PathHop { router_id });
            offset += 32;
        }
        Ok(Self { path_id, hops })
    }
}

impl PathBuildResponse {
    pub fn encode(&self) -> Result<Vec<u8>, PathBuildError> {
        let mut buf = vec![PATH_BUILD_VERSION];
        buf.extend_from_slice(&self.path_id.to_be_bytes());
        buf.push(if self.accepted { 1 } else { 0 });
        Ok(buf)
    }

    pub fn decode(input: &[u8]) -> Result<Self, PathBuildError> {
        if input.len() < 10 {
            return Err(PathBuildError::PayloadTruncated);
        }
        let version = input[0];
        if version != PATH_BUILD_VERSION {
            return Err(PathBuildError::UnsupportedPayloadVersion(version));
        }
        if input.len() > 10 {
            return Err(PathBuildError::PayloadMalformed(
                "unexpected trailing bytes",
            ));
        }
        let path_id = u64::from_be_bytes(input[1..9].try_into().unwrap());
        let accepted_byte = input[9];
        if accepted_byte > 1 {
            return Err(PathBuildError::PayloadMalformed("invalid accepted byte"));
        }
        Ok(Self {
            path_id,
            accepted: accepted_byte == 1,
        })
    }
}

impl AuthenticatedPathBuildMessage {
    pub fn sign(
        identity: &NodeIdentity,
        payload: PathBuildMessage,
    ) -> Result<Self, PathBuildError> {
        let body = payload.encode()?;
        let inner =
            AuthenticatedServiceMessage::sign(identity, ServiceMessageKind::LinkPathBuild, body)?;
        Ok(Self { inner, payload })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PathBuildError> {
        self.inner.encode().map_err(Into::into)
    }

    pub fn decode(input: &[u8]) -> Result<Self, PathBuildError> {
        Self::decode_verified(input)
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, PathBuildError> {
        let inner = AuthenticatedServiceMessage::decode_unverified(input)?;
        Self::from_authenticated_service_message(inner)
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, PathBuildError> {
        let inner = AuthenticatedServiceMessage::decode_verified(input)?;
        Self::from_authenticated_service_message(inner)
    }

    pub(crate) fn from_authenticated_service_message(
        inner: AuthenticatedServiceMessage,
    ) -> Result<Self, PathBuildError> {
        if inner.kind() != ServiceMessageKind::LinkPathBuild {
            return Err(PathBuildError::UnexpectedServiceKind);
        }
        let payload = PathBuildMessage::decode(inner.body())?;
        Ok(Self { inner, payload })
    }

    pub fn verify(&self) -> Result<(), PathBuildError> {
        self.inner.verify()?;
        if self.inner.kind() != ServiceMessageKind::LinkPathBuild {
            return Err(PathBuildError::UnexpectedServiceKind);
        }
        let encoded = self.payload.encode()?;
        if encoded != self.inner.body() {
            return Err(PathBuildError::PayloadMalformed("body mismatch"));
        }
        Ok(())
    }

    pub fn message(&self) -> &PathBuildMessage {
        &self.payload
    }
    pub fn service_message(&self) -> &AuthenticatedServiceMessage {
        &self.inner
    }
}

impl AuthenticatedPathBuildResponse {
    pub fn sign(
        identity: &NodeIdentity,
        payload: PathBuildResponse,
    ) -> Result<Self, PathBuildError> {
        let body = payload.encode()?;
        let inner = AuthenticatedServiceMessage::sign(
            identity,
            ServiceMessageKind::LinkPathBuildResponse,
            body,
        )?;
        Ok(Self { inner, payload })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PathBuildError> {
        self.inner.encode().map_err(Into::into)
    }

    pub fn decode(input: &[u8]) -> Result<Self, PathBuildError> {
        Self::decode_verified(input)
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, PathBuildError> {
        let inner = AuthenticatedServiceMessage::decode_unverified(input)?;
        Self::from_authenticated_service_message(inner)
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, PathBuildError> {
        let inner = AuthenticatedServiceMessage::decode_verified(input)?;
        Self::from_authenticated_service_message(inner)
    }

    pub(crate) fn from_authenticated_service_message(
        inner: AuthenticatedServiceMessage,
    ) -> Result<Self, PathBuildError> {
        if inner.kind() != ServiceMessageKind::LinkPathBuildResponse {
            return Err(PathBuildError::UnexpectedResponseServiceKind);
        }
        let payload = PathBuildResponse::decode(inner.body())?;
        Ok(Self { inner, payload })
    }

    pub fn verify(&self) -> Result<(), PathBuildError> {
        self.inner.verify()?;
        if self.inner.kind() != ServiceMessageKind::LinkPathBuildResponse {
            return Err(PathBuildError::UnexpectedResponseServiceKind);
        }
        let encoded = self.payload.encode()?;
        if encoded != self.inner.body() {
            return Err(PathBuildError::PayloadMalformed("body mismatch"));
        }
        Ok(())
    }

    pub fn message(&self) -> &PathBuildResponse {
        &self.payload
    }
    pub fn service_message(&self) -> &AuthenticatedServiceMessage {
        &self.inner
    }
}
