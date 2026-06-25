use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, SignatureError, SignedEnvelope,
    SignedEnvelopeCodec,
};
use saferunnet_identity::{IdentityProof, NodeIdentity};
use saferunnet_service::{
    AuthenticatedServiceMessage, AuthenticatedSessionAcceptMessage, ServiceMessageError,
    ServiceMessageKind, SessionAcceptError, SessionAcceptMessage, SessionTag,
};

const SESSION_ACCEPT_PAYLOAD_VERSION: u8 = 1;

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

fn encode_session_accept_payload_raw(session_tag: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 4);
    payload.push(SESSION_ACCEPT_PAYLOAD_VERSION);
    payload.extend_from_slice(&session_tag.to_be_bytes());
    payload
}

fn tamper_signed_service_payload(
    message: &AuthenticatedSessionAcceptMessage,
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
    let message = SessionAcceptMessage {
        session_tag: SessionTag::new(7),
    };

    let signed = AuthenticatedSessionAcceptMessage::sign(&identity, message.clone())
        .expect("sign should succeed");

    assert_eq!(signed.message(), &message);
    assert_eq!(
        signed.service_message().kind(),
        ServiceMessageKind::LinkSessionAccept
    );
    signed.verify().expect("verify should succeed");
}

#[test]
fn encode_decode_round_trip() {
    let identity = make_identity("alice");
    let message = SessionAcceptMessage {
        session_tag: SessionTag::new(99),
    };
    let signed = AuthenticatedSessionAcceptMessage::sign(&identity, message.clone())
        .expect("sign should succeed");

    let encoded = signed.encode().expect("encode should succeed");
    let decoded =
        AuthenticatedSessionAcceptMessage::decode(&encoded).expect("decode should succeed");

    assert_eq!(decoded.message(), &message);
    decoded.verify().expect("decoded message should verify");
}

#[test]
fn wrong_lower_level_service_kind_is_rejected() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        encode_session_accept_payload_raw(42),
    )
    .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let error = AuthenticatedSessionAcceptMessage::decode(&encoded)
        .expect_err("unexpected service kind should be rejected");

    assert!(matches!(
        error,
        SessionAcceptError::UnexpectedServiceKind(ServiceMessageKind::Announcement)
    ));
}

#[test]
fn tampered_signed_payload_is_rejected() {
    let identity = make_identity("alice");
    let signed = AuthenticatedSessionAcceptMessage::sign(
        &identity,
        SessionAcceptMessage {
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

    let decoded = AuthenticatedSessionAcceptMessage::decode_unverified(&encoded)
        .expect("unverified decode should parse framing and payload");
    let verify_error = decoded
        .verify()
        .expect_err("verify should fail for tampered signed payload");
    assert!(matches!(
        verify_error,
        SessionAcceptError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));

    let error = AuthenticatedSessionAcceptMessage::decode(&encoded)
        .expect_err("decode should reject payload tampering");
    assert!(matches!(
        error,
        SessionAcceptError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}

#[test]
fn unsupported_truncated_and_trailing_payload_are_rejected() {
    let identity = make_identity("alice");

    let unsupported = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkSessionAccept,
        vec![0x7f, 0, 0, 0, 0],
    )
    .expect("sign should succeed");
    let unsupported_error = AuthenticatedSessionAcceptMessage::decode(
        &unsupported.encode().expect("encode should succeed"),
    )
    .expect_err("unsupported payload version should be rejected");
    assert!(matches!(
        unsupported_error,
        SessionAcceptError::UnsupportedPayloadVersion(0x7f)
    ));

    let truncated = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkSessionAccept,
        vec![SESSION_ACCEPT_PAYLOAD_VERSION, 0xaa],
    )
    .expect("sign should succeed");
    let truncated_error = AuthenticatedSessionAcceptMessage::decode(
        &truncated.encode().expect("encode should succeed"),
    )
    .expect_err("truncated payload should be rejected");
    assert!(matches!(
        truncated_error,
        SessionAcceptError::PayloadTruncated
    ));

    let mut trailing_payload = encode_session_accept_payload_raw(12);
    trailing_payload.push(0xff);
    let trailing = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkSessionAccept,
        trailing_payload,
    )
    .expect("sign should succeed");
    let trailing_error = AuthenticatedSessionAcceptMessage::decode(
        &trailing.encode().expect("encode should succeed"),
    )
    .expect_err("trailing bytes should be rejected");
    assert!(matches!(
        trailing_error,
        SessionAcceptError::PayloadMalformed("unexpected trailing bytes in session-accept payload")
    ));
}

#[test]
fn verified_decode_prefers_authentication_failure_over_typed_parse_error_for_tampered_payload() {
    let identity = make_identity("alice");
    let signed = AuthenticatedSessionAcceptMessage::sign(
        &identity,
        SessionAcceptMessage {
            session_tag: SessionTag::new(321),
        },
    )
    .expect("sign should succeed");

    let encoded = tamper_signed_service_payload(&signed, |payload| {
        payload[6] = 0x7f;
    });

    let unverified_error = AuthenticatedSessionAcceptMessage::decode_unverified(&encoded)
        .expect_err("unverified decode should surface typed parse failure");
    assert!(matches!(
        unverified_error,
        SessionAcceptError::UnsupportedPayloadVersion(0x7f)
    ));

    let verified_error = AuthenticatedSessionAcceptMessage::decode(&encoded)
        .expect_err("verified decode should fail authentication first");
    assert!(matches!(
        verified_error,
        SessionAcceptError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}
