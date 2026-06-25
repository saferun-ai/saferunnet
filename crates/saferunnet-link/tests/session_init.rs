use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, SignatureError, SignedEnvelope,
    SignedEnvelopeCodec,
};
use saferunnet_identity::{IdentityProof, NodeIdentity};
use saferunnet_link::{
    AuthenticatedSessionInitMessage, SessionHopId, SessionInitError, SessionInitMessage,
};
use saferunnet_service::{AuthenticatedServiceMessage, ServiceMessageError, ServiceMessageKind};

const SESSION_INIT_PAYLOAD_VERSION: u8 = 1;
const ED25519_ALGORITHM_ID: u8 = 1;

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

fn encode_session_init_payload_raw(
    initiator_algorithm_id: u8,
    initiator_public_key: [u8; 32],
    local_pivot: [u8; 16],
    remote_pivot: [u8; 16],
    auth_token: Option<&[u8]>,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        1 + 1 + 32 + 16 + 16 + 1 + auth_token.map(|bytes| 2 + bytes.len()).unwrap_or(0),
    );
    payload.push(SESSION_INIT_PAYLOAD_VERSION);
    payload.push(initiator_algorithm_id);
    payload.extend_from_slice(&initiator_public_key);
    payload.extend_from_slice(&local_pivot);
    payload.extend_from_slice(&remote_pivot);
    match auth_token {
        Some(bytes) => {
            payload.push(1);
            payload.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            payload.extend_from_slice(bytes);
        }
        None => payload.push(0),
    }
    payload
}

fn tamper_signed_service_payload(
    message: &AuthenticatedSessionInitMessage,
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
fn sign_and_verify_round_trip_without_auth_token() {
    let identity = make_identity("alice");
    let message = SessionInitMessage {
        initiator: identity.public_key.clone(),
        local_pivot: hop(0x11),
        remote_pivot: hop(0x22),
        auth_token: None,
    };

    let signed = AuthenticatedSessionInitMessage::sign(&identity, message.clone())
        .expect("sign should succeed");

    assert_eq!(signed.message(), &message);
    assert_eq!(
        signed.service_message().kind(),
        ServiceMessageKind::LinkSessionInit
    );
    signed.verify().expect("verify should succeed");
}

#[test]
fn encode_decode_round_trip_with_auth_token() {
    let identity = make_identity("alice");
    let message = SessionInitMessage {
        initiator: identity.public_key.clone(),
        local_pivot: hop(0x33),
        remote_pivot: hop(0x44),
        auth_token: Some(vec![0xaa, 0xbb, 0xcc, 0xdd]),
    };

    let signed = AuthenticatedSessionInitMessage::sign(&identity, message.clone())
        .expect("sign should succeed");
    let encoded = signed.encode().expect("encode should succeed");
    let decoded = AuthenticatedSessionInitMessage::decode(&encoded).expect("decode should succeed");

    assert_eq!(decoded.message(), &message);
    decoded.verify().expect("decoded message should verify");
}

#[test]
fn wrong_lower_level_service_kind_is_rejected() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        encode_session_init_payload_raw(
            ED25519_ALGORITHM_ID,
            identity.public_key.to_bytes(),
            [0x11; 16],
            [0x22; 16],
            None,
        ),
    )
    .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let error = AuthenticatedSessionInitMessage::decode(&encoded)
        .expect_err("unexpected service kind should be rejected");

    assert!(matches!(
        error,
        SessionInitError::UnexpectedServiceKind(ServiceMessageKind::Announcement)
    ));
}

#[test]
fn tampered_signed_payload_is_rejected() {
    let identity = make_identity("alice");
    let signed = AuthenticatedSessionInitMessage::sign(
        &identity,
        SessionInitMessage {
            initiator: identity.public_key.clone(),
            local_pivot: hop(0x55),
            remote_pivot: hop(0x66),
            auth_token: Some(vec![0x01, 0x02]),
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

    let decoded = AuthenticatedSessionInitMessage::decode_unverified(&encoded)
        .expect("unverified decode should parse framing and payload");
    let verify_error = decoded
        .verify()
        .expect_err("verify should fail for tampered signed payload");
    assert!(matches!(
        verify_error,
        SessionInitError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));

    let error = AuthenticatedSessionInitMessage::decode(&encoded)
        .expect_err("decode should reject payload tampering");
    assert!(matches!(
        error,
        SessionInitError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}

#[test]
fn unsupported_algorithm_id_is_rejected() {
    let identity = make_identity("alice");
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::LinkSessionInit,
        encode_session_init_payload_raw(
            0x7f,
            identity.public_key.to_bytes(),
            [0x11; 16],
            [0x22; 16],
            None,
        ),
    )
    .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let error = AuthenticatedSessionInitMessage::decode(&encoded)
        .expect_err("unsupported algorithm id should be rejected");

    assert!(matches!(
        error,
        SessionInitError::UnsupportedInitiatorAlgorithm(0x7f)
    ));
}

#[test]
fn malformed_or_truncated_auth_token_framing_is_rejected() {
    let identity = make_identity("alice");

    let malformed =
        AuthenticatedServiceMessage::sign(&identity, ServiceMessageKind::LinkSessionInit, {
            let mut payload = encode_session_init_payload_raw(
                ED25519_ALGORITHM_ID,
                identity.public_key.to_bytes(),
                [0x11; 16],
                [0x22; 16],
                None,
            );
            let last = payload
                .len()
                .checked_sub(1)
                .expect("payload should contain auth-token flag");
            payload[last] = 0x7f;
            payload
        })
        .expect("sign should succeed");
    let malformed_error = AuthenticatedSessionInitMessage::decode(
        &malformed.encode().expect("encode should succeed"),
    )
    .expect_err("unsupported auth-token flag should be rejected");
    assert!(matches!(
        malformed_error,
        SessionInitError::PayloadMalformed("unsupported session-init auth-token flag")
    ));

    let missing_length =
        AuthenticatedServiceMessage::sign(&identity, ServiceMessageKind::LinkSessionInit, {
            let mut payload = encode_session_init_payload_raw(
                ED25519_ALGORITHM_ID,
                identity.public_key.to_bytes(),
                [0x11; 16],
                [0x22; 16],
                None,
            );
            let last = payload
                .len()
                .checked_sub(1)
                .expect("payload should contain auth-token flag");
            payload[last] = 1;
            payload
        })
        .expect("sign should succeed");
    let missing_length_error = AuthenticatedSessionInitMessage::decode(
        &missing_length.encode().expect("encode should succeed"),
    )
    .expect_err("missing auth-token length bytes should be rejected");
    assert!(matches!(
        missing_length_error,
        SessionInitError::PayloadTruncated
    ));

    let partial_length =
        AuthenticatedServiceMessage::sign(&identity, ServiceMessageKind::LinkSessionInit, {
            let mut payload = encode_session_init_payload_raw(
                ED25519_ALGORITHM_ID,
                identity.public_key.to_bytes(),
                [0x11; 16],
                [0x22; 16],
                None,
            );
            let last = payload
                .len()
                .checked_sub(1)
                .expect("payload should contain auth-token flag");
            payload[last] = 1;
            payload.push(0x00);
            payload
        })
        .expect("sign should succeed");
    let partial_length_error = AuthenticatedSessionInitMessage::decode(
        &partial_length.encode().expect("encode should succeed"),
    )
    .expect_err("partial auth-token length bytes should be rejected");
    assert!(matches!(
        partial_length_error,
        SessionInitError::PayloadTruncated
    ));

    let truncated =
        AuthenticatedServiceMessage::sign(&identity, ServiceMessageKind::LinkSessionInit, {
            let mut payload = encode_session_init_payload_raw(
                ED25519_ALGORITHM_ID,
                identity.public_key.to_bytes(),
                [0x11; 16],
                [0x22; 16],
                Some(&[0xaa, 0xbb, 0xcc]),
            );
            payload.pop();
            payload
        })
        .expect("sign should succeed");
    let truncated_error = AuthenticatedSessionInitMessage::decode(
        &truncated.encode().expect("encode should succeed"),
    )
    .expect_err("truncated auth-token bytes should be rejected");
    assert!(matches!(
        truncated_error,
        SessionInitError::PayloadTruncated
    ));
}

#[test]
fn trailing_bytes_are_rejected() {
    let identity = make_identity("alice");
    let mut payload = encode_session_init_payload_raw(
        ED25519_ALGORITHM_ID,
        identity.public_key.to_bytes(),
        [0x11; 16],
        [0x22; 16],
        Some(&[0xaa, 0xbb]),
    );
    payload.push(0xff);
    let message =
        AuthenticatedServiceMessage::sign(&identity, ServiceMessageKind::LinkSessionInit, payload)
            .expect("sign should succeed");

    let encoded = message.encode().expect("encode should succeed");
    let error = AuthenticatedSessionInitMessage::decode(&encoded)
        .expect_err("trailing bytes should be rejected");

    assert!(matches!(
        error,
        SessionInitError::PayloadMalformed("unexpected trailing bytes in session-init payload")
    ));
}

#[test]
fn verified_decode_prefers_lower_level_authentication_failure_over_typed_parse_errors() {
    let identity = make_identity("alice");
    let signed = AuthenticatedSessionInitMessage::sign(
        &identity,
        SessionInitMessage {
            initiator: identity.public_key.clone(),
            local_pivot: hop(0x77),
            remote_pivot: hop(0x88),
            auth_token: None,
        },
    )
    .expect("sign should succeed");

    let encoded = tamper_signed_service_payload(&signed, |payload| {
        payload[7] = 0x7f;
    });

    let unverified_error = AuthenticatedSessionInitMessage::decode_unverified(&encoded)
        .expect_err("unverified decode should surface the typed payload error");
    assert!(matches!(
        unverified_error,
        SessionInitError::UnsupportedInitiatorAlgorithm(0x7f)
    ));

    let verified_error = AuthenticatedSessionInitMessage::decode(&encoded)
        .expect_err("verified decode should fail lower-level signature verification first");
    assert!(matches!(
        verified_error,
        SessionInitError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}
