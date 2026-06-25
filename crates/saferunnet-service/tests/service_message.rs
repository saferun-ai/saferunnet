use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, SignatureError, SignedEnvelope,
    SignedEnvelopeCodec,
};
use saferunnet_identity::{IdentityProof, NodeIdentity};
use saferunnet_service::{AuthenticatedServiceMessage, ServiceMessageError, ServiceMessageKind};

fn make_identity(nickname: &str) -> NodeIdentity {
    let key_pair = Ed25519KeyGenerator::new()
        .generate(KeyAlgorithm::Ed25519)
        .expect("test key generation should succeed");
    NodeIdentity {
        nickname: nickname.to_string(),
        algorithm: KeyAlgorithm::Ed25519,
        secret_key: key_pair.secret_key,
        public_key: key_pair.public_key,
    }
}

fn encode_top_frame(
    proof: &IdentityProof,
    envelope: &saferunnet_crypto::SignedEnvelope,
) -> Vec<u8> {
    let proof_bytes = proof
        .encode()
        .expect("identity proof encoding should succeed in tests");
    let envelope_bytes = SignedEnvelopeCodec::encode(envelope)
        .expect("signed envelope encoding should succeed in tests");
    let mut framed = Vec::with_capacity(1 + 4 + 4 + proof_bytes.len() + envelope_bytes.len());
    framed.push(1);
    framed.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(&(envelope_bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(&proof_bytes);
    framed.extend_from_slice(&envelope_bytes);
    framed
}

fn tamper_signed_service_payload(
    message: &AuthenticatedServiceMessage,
    mutate: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let proof = message.proof().clone();
    let mut tampered_payload = message.envelope().payload().to_vec();
    mutate(&mut tampered_payload);
    let tampered_envelope = SignedEnvelope::from_parts(
        tampered_payload,
        message.envelope().signer().clone(),
        message.envelope().signature().clone(),
    );
    encode_top_frame(&proof, &tampered_envelope)
}

#[test]
fn sign_and_verify_round_trip() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        b"hello-world".to_vec(),
    )
    .expect("sign should succeed");

    assert_eq!(message.kind(), ServiceMessageKind::Announcement);
    assert_eq!(message.body(), b"hello-world");
    assert_eq!(message.proof().claim().nickname, "alice");
    message.verify().expect("verify should succeed");
}

#[test]
fn encode_decode_round_trip_preserves_payload_and_verifies() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        b"service-ready".to_vec(),
    )
    .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let decoded = AuthenticatedServiceMessage::decode(&encoded).expect("decode should succeed");

    assert_eq!(decoded.kind(), ServiceMessageKind::Announcement);
    assert_eq!(decoded.body(), b"service-ready");
    decoded.verify().expect("decoded message should verify");
}

#[test]
fn router_announcement_service_kind_round_trip_preserves_kind() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::RouterAnnouncement,
        b"router-ready".to_vec(),
    )
    .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let decoded = AuthenticatedServiceMessage::decode(&encoded).expect("decode should succeed");

    assert_eq!(decoded.kind(), ServiceMessageKind::RouterAnnouncement);
    assert_eq!(decoded.body(), b"router-ready");
    decoded.verify().expect("decoded message should verify");
}

#[test]
fn link_path_control_service_kind_round_trip_preserves_kind() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkPathControl,
        b"link-ready".to_vec(),
    )
    .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let decoded = AuthenticatedServiceMessage::decode(&encoded).expect("decode should succeed");

    assert_eq!(decoded.kind(), ServiceMessageKind::LinkPathControl);
    assert_eq!(decoded.body(), b"link-ready");
    decoded.verify().expect("decoded message should verify");
}

#[test]
fn decode_verified_accepts_valid_message() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        b"ok".to_vec(),
    )
    .expect("sign should succeed");
    let encoded = message.encode().expect("encode should succeed");

    let decoded = AuthenticatedServiceMessage::decode_verified(&encoded)
        .expect("decode_verified should succeed for a valid message");

    assert_eq!(decoded.body(), b"ok");
}

#[test]
fn tampered_signed_payload_is_rejected_by_decode() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        b"integrity".to_vec(),
    )
    .expect("sign should succeed");

    let proof = message.proof().clone();
    let mut tampered_payload = message.envelope().payload().to_vec();
    let last = tampered_payload
        .len()
        .checked_sub(1)
        .expect("payload should be non-empty");
    tampered_payload[last] ^= 0x01;
    let tampered_envelope = SignedEnvelope::from_parts(
        tampered_payload,
        message.envelope().signer().clone(),
        message.envelope().signature().clone(),
    );
    let encoded = encode_top_frame(&proof, &tampered_envelope);

    let decoded = AuthenticatedServiceMessage::decode_unverified(&encoded)
        .expect("unverified decode should parse framing and payload");
    let verify_error = decoded
        .verify()
        .expect_err("verify should fail for tampered signed payload");
    assert!(matches!(
        verify_error,
        ServiceMessageError::Signature(SignatureError::VerificationFailed)
    ));

    let error = AuthenticatedServiceMessage::decode(&encoded)
        .expect_err("decode should reject payload tampering");
    assert!(matches!(
        error,
        ServiceMessageError::Signature(SignatureError::VerificationFailed)
    ));
}

#[test]
fn decode_verified_rejects_tampered_payload_before_unsupported_payload_version_error() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        b"versioned".to_vec(),
    )
    .expect("sign should succeed");

    let encoded = tamper_signed_service_payload(&message, |payload| {
        payload[0] = 0x7f;
    });

    let unverified_error = AuthenticatedServiceMessage::decode_unverified(&encoded)
        .expect_err("unverified decode should surface the payload parse error");
    assert!(matches!(
        unverified_error,
        ServiceMessageError::FrameMalformed("unsupported service payload version")
    ));

    let verified_error = AuthenticatedServiceMessage::decode_verified(&encoded)
        .expect_err("verified decode should fail signature verification first");
    assert!(matches!(
        verified_error,
        ServiceMessageError::Signature(SignatureError::VerificationFailed)
    ));
}

#[test]
fn decode_verified_rejects_tampered_payload_before_truncated_payload_error() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        b"truncated".to_vec(),
    )
    .expect("sign should succeed");

    let encoded = tamper_signed_service_payload(&message, |payload| {
        payload.truncate(payload.len() - 1);
    });

    let unverified_error = AuthenticatedServiceMessage::decode_unverified(&encoded)
        .expect_err("unverified decode should surface the payload truncation");
    assert!(matches!(
        unverified_error,
        ServiceMessageError::FrameTruncated
    ));

    let verified_error = AuthenticatedServiceMessage::decode_verified(&encoded)
        .expect_err("verified decode should fail signature verification first");
    assert!(matches!(
        verified_error,
        ServiceMessageError::Signature(SignatureError::VerificationFailed)
    ));
}

#[test]
fn mismatched_proof_signer_and_message_signer_is_rejected() {
    let alice = make_identity("alice");
    let bob = make_identity("bob");

    let proof = IdentityProof::sign(&alice).expect("proof signing should succeed");
    let message_payload = vec![1, 1, 0, 0, 0, 3, b'b', b'o', b'b'];
    let envelope = SignedEnvelope::signed(&bob.secret_key, message_payload)
        .expect("message signing should succeed");
    let encoded = encode_top_frame(&proof, &envelope);

    let error = AuthenticatedServiceMessage::decode_verified(&encoded)
        .expect_err("decode_verified should reject mismatched signer");
    assert!(matches!(error, ServiceMessageError::SignerMismatch));
}

#[test]
fn malformed_or_truncated_top_level_framing_is_rejected() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        b"frame".to_vec(),
    )
    .expect("sign should succeed");
    let encoded = message.encode().expect("encode should succeed");

    let truncated = &encoded[..encoded.len() - 1];
    let truncated_error = AuthenticatedServiceMessage::decode(truncated)
        .expect_err("truncated bytes should be rejected");
    assert!(matches!(
        truncated_error,
        ServiceMessageError::FrameTruncated
    ));

    let mut malformed = encoded.clone();
    malformed[0] = 0x7f;
    let malformed_error = AuthenticatedServiceMessage::decode(&malformed)
        .expect_err("unknown framing version should be rejected");
    assert!(matches!(
        malformed_error,
        ServiceMessageError::UnsupportedVersion(0x7f)
    ));
}
