use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, SignatureError, SignedEnvelope,
    SignedEnvelopeCodec,
};
use saferunnet_identity::{IdentityProof, NodeIdentity};
use saferunnet_service::{
    AuthenticatedServiceMessage, AuthenticatedSessionCloseMessage, ServiceMessageError,
    ServiceMessageKind, SessionCloseError, SessionCloseMessage, SessionTag,
};

const SESSION_CLOSE_PAYLOAD_VERSION: u8 = 1;

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

fn encode_session_close_payload_raw(session_tag: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 4);
    payload.push(SESSION_CLOSE_PAYLOAD_VERSION);
    payload.extend_from_slice(&session_tag.to_be_bytes());
    payload
}

fn tamper_signed_service_payload(
    message: &AuthenticatedSessionCloseMessage,
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
    let message = SessionCloseMessage {
        session_tag: SessionTag::new(7),
    };

    let signed = AuthenticatedSessionCloseMessage::sign(&identity, message.clone())
        .expect("sign should succeed");

    assert_eq!(signed.message(), &message);
    assert_eq!(
        signed.service_message().kind(),
        ServiceMessageKind::LinkSessionClose
    );
    signed.verify().expect("verify should succeed");
}

#[test]
fn encode_decode_round_trip() {
    let identity = make_identity("alice");
    let message = SessionCloseMessage {
        session_tag: SessionTag::new(99),
    };
    let signed = AuthenticatedSessionCloseMessage::sign(&identity, message.clone())
        .expect("sign should succeed");

    let encoded = signed.encode().expect("encode should succeed");
    let decoded =
        AuthenticatedSessionCloseMessage::decode(&encoded).expect("decode should succeed");

    assert_eq!(decoded.message(), &message);
    decoded.verify().expect("decoded message should verify");
}

#[test]
fn wrong_lower_level_service_kind_is_rejected() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        encode_session_close_payload_raw(42),
    )
    .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let error = AuthenticatedSessionCloseMessage::decode(&encoded)
        .expect_err("unexpected service kind should be rejected");

    assert!(matches!(
        error,
        SessionCloseError::UnexpectedServiceKind(ServiceMessageKind::Announcement)
    ));
}

#[test]
fn tampered_signed_payload_is_rejected() {
    let identity = make_identity("alice");
    let signed = AuthenticatedSessionCloseMessage::sign(
        &identity,
        SessionCloseMessage {
            session_tag: SessionTag::new(1000),
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

    let decoded = AuthenticatedSessionCloseMessage::decode_unverified(&encoded)
        .expect("unverified decode should parse framing and payload");
    let verify_error = decoded
        .verify()
        .expect_err("verify should fail for tampered signed payload");
    assert!(matches!(
        verify_error,
        SessionCloseError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));

    let error = AuthenticatedSessionCloseMessage::decode(&encoded)
        .expect_err("decode should reject payload tampering");
    assert!(matches!(
        error,
        SessionCloseError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}

#[test]
fn unsupported_truncated_and_trailing_payload_are_rejected() {
    let identity = make_identity("alice");

    let unsupported = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkSessionClose,
        vec![0x7f, 0, 0, 0, 0],
    )
    .expect("sign should succeed");
    let unsupported_error = AuthenticatedSessionCloseMessage::decode(
        &unsupported.encode().expect("encode should succeed"),
    )
    .expect_err("unsupported payload version should be rejected");
    assert!(matches!(
        unsupported_error,
        SessionCloseError::UnsupportedPayloadVersion(0x7f)
    ));

    let truncated = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkSessionClose,
        vec![SESSION_CLOSE_PAYLOAD_VERSION, 0xaa],
    )
    .expect("sign should succeed");
    let truncated_error = AuthenticatedSessionCloseMessage::decode(
        &truncated.encode().expect("encode should succeed"),
    )
    .expect_err("truncated payload should be rejected");
    assert!(matches!(
        truncated_error,
        SessionCloseError::PayloadTruncated
    ));

    let mut trailing_payload = encode_session_close_payload_raw(12);
    trailing_payload.push(0xff);
    let trailing = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkSessionClose,
        trailing_payload,
    )
    .expect("sign should succeed");
    let trailing_error = AuthenticatedSessionCloseMessage::decode(
        &trailing.encode().expect("encode should succeed"),
    )
    .expect_err("trailing bytes should be rejected");
    assert!(matches!(
        trailing_error,
        SessionCloseError::PayloadMalformed("unexpected trailing bytes in session-close payload")
    ));
}

#[test]
fn verified_decode_prefers_authentication_failure_over_typed_parse_error_for_tampered_payload() {
    let identity = make_identity("alice");
    let signed = AuthenticatedSessionCloseMessage::sign(
        &identity,
        SessionCloseMessage {
            session_tag: SessionTag::new(321),
        },
    )
    .expect("sign should succeed");

    let encoded = tamper_signed_service_payload(&signed, |payload| {
        payload[6] = 0x7f;
    });

    let unverified_error = AuthenticatedSessionCloseMessage::decode_unverified(&encoded)
        .expect_err("unverified decode should surface typed parse failure");
    assert!(matches!(
        unverified_error,
        SessionCloseError::UnsupportedPayloadVersion(0x7f)
    ));

    let verified_error = AuthenticatedSessionCloseMessage::decode(&encoded)
        .expect_err("verified decode should fail authentication first");
    assert!(matches!(
        verified_error,
        SessionCloseError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}
