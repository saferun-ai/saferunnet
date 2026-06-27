use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, SignatureError, SignedEnvelope,
    SignedEnvelopeCodec,
};
use saferunnet_identity::{IdentityProof, NodeIdentity};
use saferunnet_service::{
    AuthenticatedServiceMessage, AuthenticatedTransitHopMessage, ServiceMessageKind,
    TransitHopError, TransitHopMessage,
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
    message: &AuthenticatedTransitHopMessage,
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
fn sign_verify_round_trip() {
    let identity = make_identity("alice");
    let message = TransitHopMessage {
        path_id: 42,
        hop_index: 0,
        encrypted_payload: vec![1, 2, 3],
    };
    let signed = AuthenticatedTransitHopMessage::sign(&identity, message.clone())
        .expect("sign should succeed");

    assert_eq!(signed.message(), &message);
    assert_eq!(
        signed.service_message().kind(),
        ServiceMessageKind::LinkTransitHop
    );
    signed.verify().expect("verify should succeed");
}

#[test]
fn encode_decode_round_trip() {
    let identity = make_identity("alice");
    let signed = AuthenticatedTransitHopMessage::sign(
        &identity,
        TransitHopMessage {
            path_id: 7,
            hop_index: 1,
            encrypted_payload: vec![0xaa, 0xbb, 0xcc],
        },
    )
    .expect("sign should succeed");

    let encoded = signed.encode().expect("encode should succeed");
    let decoded = AuthenticatedTransitHopMessage::decode(&encoded).expect("decode should succeed");

    assert_eq!(
        decoded.message(),
        &TransitHopMessage {
            path_id: 7,
            hop_index: 1,
            encrypted_payload: vec![0xaa, 0xbb, 0xcc],
        }
    );
    decoded.verify().expect("decoded message should verify");
}

#[test]
fn reject_wrong_service_kind() {
    let identity = make_identity("alice");
    let wrong_kind = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3],
    )
    .expect("sign should succeed");

    let encoded = wrong_kind.encode().expect("encode should succeed");
    let error = AuthenticatedTransitHopMessage::decode(&encoded)
        .expect_err("unexpected service kind should be rejected");

    assert!(matches!(
        error,
        TransitHopError::UnexpectedServiceKind(ServiceMessageKind::Announcement)
    ));
}

#[test]
fn reject_tampered_payload() {
    let identity = make_identity("alice");
    let signed = AuthenticatedTransitHopMessage::sign(
        &identity,
        TransitHopMessage {
            path_id: 9,
            hop_index: 2,
            encrypted_payload: vec![0x11, 0x22],
        },
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

    let decoded = AuthenticatedTransitHopMessage::decode_unverified(&encoded)
        .expect("unverified decode should parse framing and payload");
    let verify_error = decoded
        .verify()
        .expect_err("verify should fail for tampered signed payload");
    assert!(matches!(
        verify_error,
        TransitHopError::ServiceMessage(saferunnet_service::ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));

    let error = AuthenticatedTransitHopMessage::decode(&encoded)
        .expect_err("decode should reject payload tampering");
    assert!(matches!(
        error,
        TransitHopError::ServiceMessage(saferunnet_service::ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}

#[test]
fn reject_payload_too_large() {
    let identity = make_identity("alice");
    let large_payload = vec![0u8; 1025];
    let message =
        AuthenticatedServiceMessage::sign(&identity, ServiceMessageKind::LinkTransitHop, {
            let mut body = Vec::with_capacity(12 + 1025);
            body.push(1);
            body.extend_from_slice(&0u64.to_be_bytes());
            body.push(0);
            body.extend_from_slice(&1025u16.to_be_bytes());
            body.extend_from_slice(&large_payload);
            body
        })
        .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let error = AuthenticatedTransitHopMessage::decode(&encoded)
        .expect_err("payload too large should be rejected");

    assert!(matches!(
        error,
        TransitHopError::PayloadTooLarge {
            max: 1024,
            found: 1025,
        }
    ));
}

#[test]
fn reject_unsupported_version() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkTransitHop,
        vec![0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1],
    )
    .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let error = AuthenticatedTransitHopMessage::decode(&encoded)
        .expect_err("unsupported version should be rejected");

    assert!(matches!(error, TransitHopError::UnsupportedVersion(0x7f)));
}

#[test]
fn reject_truncated() {
    let identity = make_identity("alice");
    let truncated = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkTransitHop,
        vec![1, 0, 0, 0, 0, 0, 0, 0, 0],
    )
    .expect("sign should succeed");

    let encoded = truncated.encode().expect("encode should succeed");
    let error = AuthenticatedTransitHopMessage::decode(&encoded)
        .expect_err("truncated payload should be rejected");

    assert!(matches!(error, TransitHopError::PayloadTruncated));
}

#[test]
fn reject_trailing_bytes() {
    let identity = make_identity("alice");
    let message =
        AuthenticatedServiceMessage::sign(&identity, ServiceMessageKind::LinkTransitHop, {
            let mut body = Vec::new();
            body.push(1);
            body.extend_from_slice(&0u64.to_be_bytes());
            body.push(0);
            body.extend_from_slice(&2u16.to_be_bytes());
            body.extend_from_slice(&[0xaa, 0xbb]);
            body.push(0xff);
            body
        })
        .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let error = AuthenticatedTransitHopMessage::decode(&encoded)
        .expect_err("trailing bytes should be rejected");

    assert!(matches!(
        error,
        TransitHopError::PayloadMalformed("unexpected trailing bytes in transit hop payload")
    ));
}

#[test]
fn reject_truncated_encrypted_payload() {
    let identity = make_identity("alice");
    let message =
        AuthenticatedServiceMessage::sign(&identity, ServiceMessageKind::LinkTransitHop, {
            let mut body = Vec::new();
            body.push(1);
            body.extend_from_slice(&0u64.to_be_bytes());
            body.push(0);
            body.extend_from_slice(&4u16.to_be_bytes());
            body.extend_from_slice(&[0xaa, 0xbb]);
            body
        })
        .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let error = AuthenticatedTransitHopMessage::decode(&encoded)
        .expect_err("declared payload length mismatch should be rejected");

    assert!(matches!(
        error,
        TransitHopError::PayloadLengthMismatch {
            declared: 4,
            remaining: 2,
        }
    ));
}

#[test]
fn verified_decode_authenticates_before_typed_parse() {
    let identity = make_identity("alice");
    let signed = AuthenticatedTransitHopMessage::sign(
        &identity,
        TransitHopMessage {
            path_id: 11,
            hop_index: 0,
            encrypted_payload: vec![0xdd, 0xee],
        },
    )
    .expect("sign should succeed");

    let encoded = tamper_signed_service_payload(&signed, |payload| {
        payload[6] = 0x7f;
    });

    let unverified_error = AuthenticatedTransitHopMessage::decode_unverified(&encoded)
        .expect_err("unverified decode should surface the typed payload error");
    assert!(matches!(
        unverified_error,
        TransitHopError::UnsupportedVersion(0x7f)
    ));

    let verified_error = AuthenticatedTransitHopMessage::decode(&encoded)
        .expect_err("verified decode should fail lower-level signature verification first");
    assert!(matches!(
        verified_error,
        TransitHopError::ServiceMessage(saferunnet_service::ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}
