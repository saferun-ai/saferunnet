use crate::contact::{IdentityProof, IdentityProofError, NodeIdentity};
use saferunnet_crypto::{EnvelopeCodecError, SignatureError, SignedEnvelope, SignedEnvelopeCodec};
use thiserror::Error;

mod session_accept;
mod session_close;
mod session_init;
mod session_path_switch;
pub mod session_state;
mod session_types;
pub mod session_manager;

pub use session_accept::{
    AuthenticatedSessionAcceptMessage, SessionAcceptError, SessionAcceptMessage,
};
pub use session_close::{AuthenticatedSessionCloseMessage, SessionCloseError, SessionCloseMessage};
pub use session_init::{AuthenticatedSessionInitMessage, SessionInitError, SessionInitMessage};
pub use session_path_switch::{
    AuthenticatedSessionPathSwitchMessage, SessionPathSwitchError, SessionPathSwitchMessage,
};
pub use session_state::{ActiveSession, SessionState, SessionStateError};
pub use session_types::{SessionHopId, SessionTag};

const SERVICE_FRAME_VERSION: u8 = 1;
const SERVICE_FRAME_HEADER_LEN: usize = 9;
const SERVICE_PAYLOAD_VERSION: u8 = 1;
const SERVICE_PAYLOAD_HEADER_LEN: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMessageKind {
    Announcement,
    RouterAnnouncement,
    LinkPathControl,
    LinkSessionInit,
    LinkSessionPathSwitch,
    LinkSessionAccept,
    LinkSessionClose,
    DhtIntro,
    LinkPathBuild,
    LinkPathBuildResponse,
    LinkTransitHop,
    ExitAnnounce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedServiceMessage {
    proof: IdentityProof,
    kind: ServiceMessageKind,
    body: Vec<u8>,
    envelope: SignedEnvelope,
}

impl AuthenticatedServiceMessage {
    pub fn sign(
        identity: &NodeIdentity,
        kind: ServiceMessageKind,
        body: Vec<u8>,
    ) -> Result<Self, ServiceMessageError> {
        let proof = IdentityProof::sign(identity)?;
        let payload = encode_service_payload(kind, &body)?;
        let envelope = SignedEnvelope::signed(&identity.secret_key, payload)?;
        Ok(Self {
            proof,
            kind,
            body,
            envelope,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceMessageError> {
        let proof_bytes = self.proof.encode()?;
        let envelope_bytes = SignedEnvelopeCodec::encode(&self.envelope)?;
        let proof_len = u32::try_from(proof_bytes.len()).map_err(|_| {
            ServiceMessageError::FrameLengthOverflow {
                field: "proof",
                length: proof_bytes.len(),
                max: u32::MAX as usize,
            }
        })?;
        let envelope_len = u32::try_from(envelope_bytes.len()).map_err(|_| {
            ServiceMessageError::FrameLengthOverflow {
                field: "envelope",
                length: envelope_bytes.len(),
                max: u32::MAX as usize,
            }
        })?;
        let mut encoded =
            Vec::with_capacity(SERVICE_FRAME_HEADER_LEN + proof_bytes.len() + envelope_bytes.len());
        encoded.push(SERVICE_FRAME_VERSION);
        encoded.extend_from_slice(&proof_len.to_be_bytes());
        encoded.extend_from_slice(&envelope_len.to_be_bytes());
        encoded.extend_from_slice(&proof_bytes);
        encoded.extend_from_slice(&envelope_bytes);
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ServiceMessageError> {
        Self::decode_verified(input)
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, ServiceMessageError> {
        let (proof, envelope) = decode_service_frame(input)?;
        let (kind, body) = decode_service_payload(envelope.payload())?;
        Ok(Self {
            proof,
            kind,
            body,
            envelope,
        })
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, ServiceMessageError> {
        let (proof, envelope) = decode_service_frame(input)?;
        verify_service_envelope(&proof, &envelope)?;
        let (kind, body) = decode_service_payload(envelope.payload())?;
        Ok(Self {
            proof,
            kind,
            body,
            envelope,
        })
    }

    pub fn proof(&self) -> &IdentityProof {
        &self.proof
    }

    pub fn kind(&self) -> ServiceMessageKind {
        self.kind
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn envelope(&self) -> &SignedEnvelope {
        &self.envelope
    }

    pub fn verify(&self) -> Result<(), ServiceMessageError> {
        verify_service_envelope(&self.proof, &self.envelope)
    }
}

#[derive(Debug, Error)]
pub enum ServiceMessageError {
    #[error("service message frame truncated")]
    FrameTruncated,
    #[error("unsupported service frame version: {0}")]
    UnsupportedVersion(u8),
    #[error("service message frame malformed: {0}")]
    FrameMalformed(&'static str),
    #[error("service message signer mismatch")]
    SignerMismatch,
    #[error(transparent)]
    Signature(#[from] SignatureError),
    #[error(transparent)]
    EnvelopeCodec(#[from] EnvelopeCodecError),
    #[error(transparent)]
    IdentityProof(#[from] IdentityProofError),
    #[error("message kind mismatch: expected {expected:?}, got {got:?}")]
    KindMismatch {
        expected: ServiceMessageKind,
        got: ServiceMessageKind,
    },
    #[error("frame field `{field}` exceeds encoded limit `{max}` with `{length}` bytes")]
    FrameLengthOverflow {
        field: &'static str,
        length: usize,
        max: usize,
    },
    #[error("payload field `{field}` exceeds encoded limit `{max}` with `{length}` bytes")]
    PayloadLengthOverflow {
        field: &'static str,
        length: usize,
        max: usize,
    },
}

fn encode_service_payload(
    kind: ServiceMessageKind,
    body: &[u8],
) -> Result<Vec<u8>, ServiceMessageError> {
    let body_len =
        u32::try_from(body.len()).map_err(|_| ServiceMessageError::PayloadLengthOverflow {
            field: "body",
            length: body.len(),
            max: u32::MAX as usize,
        })?;
    let mut payload = Vec::with_capacity(SERVICE_PAYLOAD_HEADER_LEN + body.len());
    payload.push(SERVICE_PAYLOAD_VERSION);
    payload.push(encode_kind(kind));
    payload.extend_from_slice(&body_len.to_be_bytes());
    payload.extend_from_slice(body);
    Ok(payload)
}

fn decode_service_frame(
    input: &[u8],
) -> Result<(IdentityProof, SignedEnvelope), ServiceMessageError> {
    if input.len() < SERVICE_FRAME_HEADER_LEN {
        return Err(ServiceMessageError::FrameTruncated);
    }

    let mut cursor = input;
    let version = take_frame_exact(&mut cursor, 1)?[0];
    if version != SERVICE_FRAME_VERSION {
        return Err(ServiceMessageError::UnsupportedVersion(version));
    }

    let proof_len = u32::from_be_bytes(
        take_frame_exact(&mut cursor, 4)?
            .try_into()
            .expect("take_frame_exact guarantees exact byte count"),
    ) as usize;
    let envelope_len = u32::from_be_bytes(
        take_frame_exact(&mut cursor, 4)?
            .try_into()
            .expect("take_frame_exact guarantees exact byte count"),
    ) as usize;
    let proof = IdentityProof::decode(take_frame_exact(&mut cursor, proof_len)?)?;
    let envelope = SignedEnvelopeCodec::decode(take_frame_exact(&mut cursor, envelope_len)?)?;

    if !cursor.is_empty() {
        return Err(ServiceMessageError::FrameMalformed(
            "unexpected trailing bytes in service message frame",
        ));
    }

    Ok((proof, envelope))
}

fn decode_service_payload(
    input: &[u8],
) -> Result<(ServiceMessageKind, Vec<u8>), ServiceMessageError> {
    if input.len() < SERVICE_PAYLOAD_HEADER_LEN {
        return Err(ServiceMessageError::FrameTruncated);
    }
    let mut cursor = input;
    let payload_version = take_frame_exact(&mut cursor, 1)?[0];
    if payload_version != SERVICE_PAYLOAD_VERSION {
        return Err(ServiceMessageError::FrameMalformed(
            "unsupported service payload version",
        ));
    }
    let kind = decode_kind(take_frame_exact(&mut cursor, 1)?[0])?;
    let body_len = u32::from_be_bytes(
        take_frame_exact(&mut cursor, 4)?
            .try_into()
            .expect("take_frame_exact guarantees exact byte count"),
    ) as usize;
    let body = take_frame_exact(&mut cursor, body_len)?.to_vec();
    if !cursor.is_empty() {
        return Err(ServiceMessageError::FrameMalformed(
            "unexpected trailing bytes in service payload",
        ));
    }
    Ok((kind, body))
}

fn verify_service_envelope(
    proof: &IdentityProof,
    envelope: &SignedEnvelope,
) -> Result<(), ServiceMessageError> {
    proof.verify()?;
    envelope
        .verify_signed_by(&proof.claim().public_key)
        .map_err(|error| match error {
            SignatureError::ExpectedSignerMismatch => ServiceMessageError::SignerMismatch,
            other => ServiceMessageError::Signature(other),
        })?;
    Ok(())
}

fn encode_kind(kind: ServiceMessageKind) -> u8 {
    match kind {
        ServiceMessageKind::Announcement => 1,
        ServiceMessageKind::RouterAnnouncement => 2,
        ServiceMessageKind::LinkPathControl => 3,
        ServiceMessageKind::LinkSessionInit => 4,
        ServiceMessageKind::LinkSessionPathSwitch => 5,
        ServiceMessageKind::LinkSessionAccept => 6,
        ServiceMessageKind::LinkSessionClose => 7,
        ServiceMessageKind::DhtIntro => 8,
        ServiceMessageKind::LinkPathBuild => 9,
        ServiceMessageKind::LinkPathBuildResponse => 10,
        ServiceMessageKind::LinkTransitHop => 11,
        ServiceMessageKind::ExitAnnounce => 12,
    }
}

fn decode_kind(encoded: u8) -> Result<ServiceMessageKind, ServiceMessageError> {
    match encoded {
        1 => Ok(ServiceMessageKind::Announcement),
        2 => Ok(ServiceMessageKind::RouterAnnouncement),
        3 => Ok(ServiceMessageKind::LinkPathControl),
        4 => Ok(ServiceMessageKind::LinkSessionInit),
        5 => Ok(ServiceMessageKind::LinkSessionPathSwitch),
        6 => Ok(ServiceMessageKind::LinkSessionAccept),
        7 => Ok(ServiceMessageKind::LinkSessionClose),
        8 => Ok(ServiceMessageKind::DhtIntro),
        9 => Ok(ServiceMessageKind::LinkPathBuild),
        10 => Ok(ServiceMessageKind::LinkPathBuildResponse),
        11 => Ok(ServiceMessageKind::LinkTransitHop),
        12 => Ok(ServiceMessageKind::ExitAnnounce),
        _ => Err(ServiceMessageError::FrameMalformed(
            "unsupported service message kind",
        )),
    }
}

fn take_frame_exact<'a>(
    input: &mut &'a [u8],
    count: usize,
) -> Result<&'a [u8], ServiceMessageError> {
    if input.len() < count {
        return Err(ServiceMessageError::FrameTruncated);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}

