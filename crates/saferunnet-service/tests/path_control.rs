use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, SignatureError, SignedEnvelope,
    SignedEnvelopeCodec,
};
use saferunnet_identity::{IdentityProof, NodeIdentity};
use saferunnet_service::{
    AuthenticatedPathControlMessage, AuthenticatedServiceMessage, PathControlError,
    PathControlMessage, PathLatency, PathPing, ServiceMessageKind,
};

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
    message: &AuthenticatedPathControlMessage,
    mutate: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let proof = message.service_message().proof().clone();
    let mut tampered_payload = message.service_message().envelope().payload().to_vec();
    mutate(&mut tampered_payload);
    let tampered_envelope = SignedEnvelope::from_parts(
        tampered_payload,
        message.service_message().envelope().signer().clone(),
        message.service_message().envelope().signature().clone(),
    );
    encode_top_frame(&proof, &tampered_envelope)
}

#[test]
fn sign_and_verify_round_trip() {
    let identity = make_identity("alice");
    let message = PathControlMessage::Ping(PathPing { request_id: 42 });
    let signed = AuthenticatedPathControlMessage::sign(&identity, message.clone())
        .expect("sign should succeed");

    assert_eq!(signed.message(), &message);
    assert_eq!(
        signed.service_message().kind(),
        ServiceMessageKind::LinkPathControl
    );
    signed.verify().expect("verify should succeed");
}

#[test]
fn encode_decode_round_trip_preserves_payload_and_verifies() {
    let identity = make_identity("alice");
    let signed = AuthenticatedPathControlMessage::sign(
        &identity,
        PathControlMessage::Ping(PathPing { request_id: 7 }),
    )
    .expect("sign should succeed");

    let encoded = signed.encode().expect("encode should succeed");
    let decoded = AuthenticatedPathControlMessage::decode(&encoded).expect("decode should succeed");

    assert_eq!(
        decoded.message(),
        &PathControlMessage::Ping(PathPing { request_id: 7 })
    );
    decoded.verify().expect("decoded message should verify");
}

#[test]
fn wrong_lower_level_service_kind_is_rejected() {
    let identity = make_identity("alice");
    let wrong_kind = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 9],
    )
    .expect("sign should succeed");

    let encoded = wrong_kind.encode().expect("encode should succeed");
    let error = AuthenticatedPathControlMessage::decode(&encoded)
        .expect_err("unexpected service kind should be rejected");

    assert!(matches!(
        error,
        PathControlError::UnexpectedServiceKind(ServiceMessageKind::Announcement)
    ));
}

#[test]
fn tampered_signed_payload_is_rejected() {
    let identity = make_identity("alice");
    let signed = AuthenticatedPathControlMessage::sign(
        &identity,
        PathControlMessage::Ping(PathPing { request_id: 9 }),
    )
    .expect("sign should succeed");

    let proof = signed.service_message().proof().clone();
    let mut tampered_payload = signed.service_message().envelope().payload().to_vec();
    let last = tampered_payload
        .len()
        .checked_sub(1)
        .expect("payload should be non-empty");
    tampered_payload[last] ^= 0x01;
    let tampered_envelope = SignedEnvelope::from_parts(
        tampered_payload,
        signed.service_message().envelope().signer().clone(),
        signed.service_message().envelope().signature().clone(),
    );
    let encoded = encode_top_frame(&proof, &tampered_envelope);

    let decoded = AuthenticatedPathControlMessage::decode_unverified(&encoded)
        .expect("unverified decode should parse framing and payload");
    let verify_error = decoded
        .verify()
        .expect_err("verify should fail for tampered signed payload");
    assert!(matches!(
        verify_error,
        PathControlError::ServiceMessage(saferunnet_service::ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));

    let error = AuthenticatedPathControlMessage::decode(&encoded)
        .expect_err("decode should reject payload tampering");
    assert!(matches!(
        error,
        PathControlError::ServiceMessage(saferunnet_service::ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}

#[test]
fn decode_rejects_tampered_variant_before_typed_payload_errors() {
    let identity = make_identity("alice");
    let signed = AuthenticatedPathControlMessage::sign(
        &identity,
        PathControlMessage::Ping(PathPing { request_id: 11 }),
    )
    .expect("sign should succeed");

    let encoded = tamper_signed_service_payload(&signed, |payload| {
        payload[7] = 0x7f;
    });

    let unverified_error = AuthenticatedPathControlMessage::decode_unverified(&encoded)
        .expect_err("unverified decode should surface the typed payload error");
    assert!(matches!(
        unverified_error,
        PathControlError::PayloadMalformed("unsupported path control variant id")
    ));

    let verified_error = AuthenticatedPathControlMessage::decode(&encoded)
        .expect_err("verified decode should fail lower-level signature verification first");
    assert!(matches!(
        verified_error,
        PathControlError::ServiceMessage(saferunnet_service::ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}

#[test]
fn unsupported_path_control_variant_is_rejected_before_ping_width_parsing() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkPathControl,
        vec![1, 0x7f],
    )
    .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let error = AuthenticatedPathControlMessage::decode(&encoded)
        .expect_err("unsupported variant should be rejected");

    assert!(matches!(
        error,
        PathControlError::PayloadMalformed("unsupported path control variant id")
    ));
}

#[test]
fn trailing_bytes_in_link_payload_are_rejected() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkPathControl,
        vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0xaa],
    )
    .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let error = AuthenticatedPathControlMessage::decode(&encoded)
        .expect_err("trailing bytes should be rejected");

    assert!(matches!(
        error,
        PathControlError::PayloadMalformed("unexpected trailing bytes in path control payload")
    ));
}

#[test]
fn unsupported_or_truncated_link_payload_is_rejected() {
    let identity = make_identity("alice");

    let unsupported = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkPathControl,
        vec![0x7f, 1, 0, 0, 0, 0, 0, 0, 0, 1],
    )
    .expect("sign should succeed");
    let unsupported_error = AuthenticatedPathControlMessage::decode(
        &unsupported.encode().expect("encode should succeed"),
    )
    .expect_err("unsupported payload version should be rejected");
    assert!(matches!(
        unsupported_error,
        PathControlError::UnsupportedPayloadVersion(0x7f)
    ));

    let truncated = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkPathControl,
        vec![1, 1, 0, 0, 0, 0, 0, 0],
    )
    .expect("sign should succeed");
    let truncated_error = AuthenticatedPathControlMessage::decode(
        &truncated.encode().expect("encode should succeed"),
    )
    .expect_err("truncated payload should be rejected");
    assert!(matches!(
        truncated_error,
        PathControlError::PayloadTruncated
    ));
}

#[test]
fn latency_sign_and_verify_round_trip() {
    let identity = make_identity("alice");
    let msg = PathControlMessage::Latency(PathLatency {
        path_id: 42,
        latency_us: 1500,
    });
    let signed = AuthenticatedPathControlMessage::sign(&identity, msg).expect("sign");
    signed.verify().expect("verify");
}

#[test]
fn latency_encode_decode_round_trip() {
    let identity = make_identity("alice");
    let msg = PathControlMessage::Latency(PathLatency {
        path_id: 7,
        latency_us: 999,
    });
    let signed = AuthenticatedPathControlMessage::sign(&identity, msg).expect("sign");
    let encoded = signed.encode().expect("encode");
    let decoded = AuthenticatedPathControlMessage::decode(&encoded).expect("decode");
    match decoded.message() {
        PathControlMessage::Latency(l) => {
            assert_eq!(l.path_id, 7);
            assert_eq!(l.latency_us, 999);
        }
        _ => panic!("expected latency variant"),
    }
}

#[test]
fn latency_tampered_payload_is_rejected() {
    let identity = make_identity("alice");
    let msg = PathControlMessage::Latency(PathLatency {
        path_id: 1,
        latency_us: 100,
    });
    let signed = AuthenticatedPathControlMessage::sign(&identity, msg).expect("sign");
    let mut encoded = signed.encode().expect("encode");
    encoded[20] ^= 0xff;
    assert!(AuthenticatedPathControlMessage::decode(&encoded).is_err());
}
