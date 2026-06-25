use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, SignatureError, SignedEnvelope,
    SignedEnvelopeCodec,
};
use saferunnet_identity::{IdentityProof, NodeIdentity};
use saferunnet_link::{
    AuthenticatedSessionPathSwitchMessage, SessionHopId, SessionPathSwitchError,
    SessionPathSwitchMessage, SessionTag,
};
use saferunnet_service::{AuthenticatedServiceMessage, ServiceMessageError, ServiceMessageKind};

const SESSION_PATH_SWITCH_PAYLOAD_VERSION: u8 = 1;

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

fn hop(seed: u8) -> SessionHopId {
    SessionHopId::new([seed; 16])
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

fn encode_session_path_switch_payload_raw(
    local_pivot: [u8; 16],
    remote_pivot: [u8; 16],
    session_tag: u32,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 16 + 16 + 4);
    payload.push(SESSION_PATH_SWITCH_PAYLOAD_VERSION);
    payload.extend_from_slice(&local_pivot);
    payload.extend_from_slice(&remote_pivot);
    payload.extend_from_slice(&session_tag.to_be_bytes());
    payload
}

fn tamper_signed_service_payload(
    message: &AuthenticatedSessionPathSwitchMessage,
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
    let message = SessionPathSwitchMessage {
        local_pivot: hop(0x11),
        remote_pivot: hop(0x22),
        session_tag: SessionTag::new(7),
    };

    let signed = AuthenticatedSessionPathSwitchMessage::sign(&identity, message.clone())
        .expect("sign should succeed");

    assert_eq!(signed.message(), &message);
    assert_eq!(
        signed.service_message().kind(),
        ServiceMessageKind::LinkSessionPathSwitch
    );
    signed.verify().expect("verify should succeed");
}

#[test]
fn encode_decode_round_trip() {
    let identity = make_identity("alice");
    let message = SessionPathSwitchMessage {
        local_pivot: hop(0x33),
        remote_pivot: hop(0x44),
        session_tag: SessionTag::new(99),
    };
    let signed = AuthenticatedSessionPathSwitchMessage::sign(&identity, message.clone())
        .expect("sign should succeed");

    let encoded = signed.encode().expect("encode should succeed");
    let decoded =
        AuthenticatedSessionPathSwitchMessage::decode(&encoded).expect("decode should succeed");

    assert_eq!(decoded.message(), &message);
    decoded.verify().expect("decoded message should verify");
}

#[test]
fn wrong_lower_level_service_kind_is_rejected() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        encode_session_path_switch_payload_raw([0x11; 16], [0x22; 16], 42),
    )
    .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let error = AuthenticatedSessionPathSwitchMessage::decode(&encoded)
        .expect_err("unexpected service kind should be rejected");

    assert!(matches!(
        error,
        SessionPathSwitchError::UnexpectedServiceKind(ServiceMessageKind::Announcement)
    ));
}

#[test]
fn tampered_signed_payload_is_rejected() {
    let identity = make_identity("alice");
    let signed = AuthenticatedSessionPathSwitchMessage::sign(
        &identity,
        SessionPathSwitchMessage {
            local_pivot: hop(0x55),
            remote_pivot: hop(0x66),
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

    let decoded = AuthenticatedSessionPathSwitchMessage::decode_unverified(&encoded)
        .expect("unverified decode should parse framing and payload");
    let verify_error = decoded
        .verify()
        .expect_err("verify should fail for tampered signed payload");
    assert!(matches!(
        verify_error,
        SessionPathSwitchError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));

    let error = AuthenticatedSessionPathSwitchMessage::decode(&encoded)
        .expect_err("decode should reject payload tampering");
    assert!(matches!(
        error,
        SessionPathSwitchError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}

#[test]
fn unsupported_truncated_and_trailing_payload_are_rejected() {
    let identity = make_identity("alice");

    let unsupported =
        AuthenticatedServiceMessage::sign(&identity, ServiceMessageKind::LinkSessionPathSwitch, {
            let mut payload = vec![0; 1 + 16 + 16 + 4];
            payload[0] = 0x7f;
            payload
        })
        .expect("sign should succeed");
    let unsupported_error = AuthenticatedSessionPathSwitchMessage::decode(
        &unsupported.encode().expect("encode should succeed"),
    )
    .expect_err("unsupported payload version should be rejected");
    assert!(matches!(
        unsupported_error,
        SessionPathSwitchError::UnsupportedPayloadVersion(0x7f)
    ));

    let truncated = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkSessionPathSwitch,
        vec![SESSION_PATH_SWITCH_PAYLOAD_VERSION, 0xaa],
    )
    .expect("sign should succeed");
    let truncated_error = AuthenticatedSessionPathSwitchMessage::decode(
        &truncated.encode().expect("encode should succeed"),
    )
    .expect_err("truncated payload should be rejected");
    assert!(matches!(
        truncated_error,
        SessionPathSwitchError::PayloadTruncated
    ));

    let mut trailing_payload = encode_session_path_switch_payload_raw([0x11; 16], [0x22; 16], 12);
    trailing_payload.push(0xff);
    let trailing = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkSessionPathSwitch,
        trailing_payload,
    )
    .expect("sign should succeed");
    let trailing_error = AuthenticatedSessionPathSwitchMessage::decode(
        &trailing.encode().expect("encode should succeed"),
    )
    .expect_err("trailing bytes should be rejected");
    assert!(matches!(
        trailing_error,
        SessionPathSwitchError::PayloadMalformed(
            "unexpected trailing bytes in session-path-switch payload"
        )
    ));
}

#[test]
fn verified_decode_prefers_authentication_failure_over_typed_parse_error_for_tampered_payload() {
    let identity = make_identity("alice");
    let signed = AuthenticatedSessionPathSwitchMessage::sign(
        &identity,
        SessionPathSwitchMessage {
            local_pivot: hop(0x77),
            remote_pivot: hop(0x88),
            session_tag: SessionTag::new(321),
        },
    )
    .expect("sign should succeed");

    let encoded = tamper_signed_service_payload(&signed, |payload| {
        payload[6] = 0x7f;
    });

    let unverified_error = AuthenticatedSessionPathSwitchMessage::decode_unverified(&encoded)
        .expect_err("unverified decode should surface typed parse failure");
    assert!(matches!(
        unverified_error,
        SessionPathSwitchError::UnsupportedPayloadVersion(0x7f)
    ));

    let verified_error = AuthenticatedSessionPathSwitchMessage::decode(&encoded)
        .expect_err("verified decode should fail authentication first");
    assert!(matches!(
        verified_error,
        SessionPathSwitchError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}
