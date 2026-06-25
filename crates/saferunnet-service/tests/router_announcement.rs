use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, SignatureError, SignedEnvelope,
    SignedEnvelopeCodec,
};
use saferunnet_identity::{IdentityProof, NodeIdentity};
use saferunnet_service::{
    AuthenticatedRouterAnnouncement, AuthenticatedServiceMessage, RouterAnnouncement,
    RouterAnnouncementError, RouterCapability, ServiceMessageError, ServiceMessageKind,
};

const ROUTER_PAYLOAD_VERSION: u8 = 1;

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

fn encode_service_frame(
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

fn encode_router_payload_raw(sequence: u64, capabilities: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 8 + 2 + capabilities.len());
    payload.push(ROUTER_PAYLOAD_VERSION);
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.extend_from_slice(&(capabilities.len() as u16).to_be_bytes());
    payload.extend_from_slice(capabilities);
    payload
}

#[test]
fn sign_and_verify_round_trip() {
    let identity = make_identity("router-a");
    let announcement = RouterAnnouncement {
        sequence: 7,
        capabilities: vec![RouterCapability::Relay, RouterCapability::Exit],
    };

    let signed = AuthenticatedRouterAnnouncement::sign(&identity, announcement.clone())
        .expect("sign should succeed");

    assert_eq!(signed.announcement(), &announcement);
    assert_eq!(
        signed.service_message().kind(),
        ServiceMessageKind::RouterAnnouncement
    );
    signed.verify().expect("verify should succeed");
}

#[test]
fn encode_decode_round_trip_preserves_payload_and_verifies() {
    let identity = make_identity("router-a");
    let announcement = RouterAnnouncement {
        sequence: 42,
        capabilities: vec![RouterCapability::Exit],
    };
    let signed = AuthenticatedRouterAnnouncement::sign(&identity, announcement.clone())
        .expect("sign should succeed");

    let encoded = signed.encode().expect("encode should succeed");
    let decoded = AuthenticatedRouterAnnouncement::decode(&encoded).expect("decode should succeed");

    assert_eq!(decoded.announcement(), &announcement);
    decoded
        .verify()
        .expect("decoded announcement should verify");
}

#[test]
fn wrong_lower_level_service_kind_is_rejected() {
    let identity = make_identity("router-a");
    let signed = AuthenticatedRouterAnnouncement::sign(
        &identity,
        RouterAnnouncement {
            sequence: 9,
            capabilities: vec![RouterCapability::Relay],
        },
    )
    .expect("sign should succeed");

    let wrong_kind = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        signed.service_message().body().to_vec(),
    )
    .expect("lower-level signing should succeed");
    let encoded = wrong_kind.encode().expect("encode should succeed");

    let error = AuthenticatedRouterAnnouncement::decode(&encoded)
        .expect_err("wrong lower-level service kind must be rejected");
    assert!(matches!(
        error,
        RouterAnnouncementError::UnexpectedServiceKind(ServiceMessageKind::Announcement)
    ));
}

#[test]
fn tampered_signed_payload_is_rejected() {
    let identity = make_identity("router-a");
    let signed = AuthenticatedRouterAnnouncement::sign(
        &identity,
        RouterAnnouncement {
            sequence: 11,
            capabilities: vec![RouterCapability::Relay],
        },
    )
    .expect("sign should succeed");

    let proof = signed.service_message().proof().clone();
    let mut tampered_payload = signed.service_message().envelope().payload().to_vec();
    let last = tampered_payload
        .len()
        .checked_sub(1)
        .expect("payload should be non-empty");
    tampered_payload[last] = 2;
    let tampered_envelope = SignedEnvelope::from_parts(
        tampered_payload,
        signed.service_message().envelope().signer().clone(),
        signed.service_message().envelope().signature().clone(),
    );
    let encoded = encode_service_frame(&proof, &tampered_envelope);

    let decoded = AuthenticatedRouterAnnouncement::decode_unverified(&encoded)
        .expect("unverified decode should still parse the tampered payload");
    let verify_error = decoded
        .verify()
        .expect_err("verify should fail for tampered signed payload");
    assert!(matches!(
        verify_error,
        RouterAnnouncementError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));

    let error = AuthenticatedRouterAnnouncement::decode(&encoded)
        .expect_err("verified decode should reject tampering");
    assert!(matches!(
        error,
        RouterAnnouncementError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}

#[test]
fn decode_verified_rejects_tampered_payload_before_unsupported_payload_version_error() {
    let identity = make_identity("router-a");
    let signed = AuthenticatedRouterAnnouncement::sign(
        &identity,
        RouterAnnouncement {
            sequence: 15,
            capabilities: vec![RouterCapability::Exit],
        },
    )
    .expect("sign should succeed");

    let proof = signed.service_message().proof().clone();
    let mut tampered_payload = signed.service_message().envelope().payload().to_vec();
    tampered_payload[6] = 0x7f;
    let tampered_envelope = SignedEnvelope::from_parts(
        tampered_payload,
        signed.service_message().envelope().signer().clone(),
        signed.service_message().envelope().signature().clone(),
    );
    let encoded = encode_service_frame(&proof, &tampered_envelope);

    let unverified_error = AuthenticatedRouterAnnouncement::decode_unverified(&encoded)
        .expect_err("unverified decode should surface the typed payload parse error");
    assert!(matches!(
        unverified_error,
        RouterAnnouncementError::UnsupportedPayloadVersion(0x7f)
    ));

    let verified_error = AuthenticatedRouterAnnouncement::decode_verified(&encoded)
        .expect_err("verified decode should fail signature verification first");
    assert!(matches!(
        verified_error,
        RouterAnnouncementError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}

#[test]
fn duplicate_capabilities_are_rejected() {
    let identity = make_identity("router-a");
    let duplicate_payload = encode_router_payload_raw(3, &[1, 1]);
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::RouterAnnouncement,
        duplicate_payload,
    )
    .expect("lower-level signing should succeed");
    let encoded = message.encode().expect("encode should succeed");

    let error = AuthenticatedRouterAnnouncement::decode(&encoded)
        .expect_err("duplicate capabilities must be rejected");
    assert!(matches!(
        error,
        RouterAnnouncementError::DuplicateCapability(RouterCapability::Relay)
    ));
}

#[test]
fn unsupported_capability_id_is_rejected_as_malformed_payload() {
    let identity = make_identity("router-a");
    let malformed_payload = encode_router_payload_raw(5, &[1, 3]);
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::RouterAnnouncement,
        malformed_payload,
    )
    .expect("lower-level signing should succeed");
    let encoded = message.encode().expect("encode should succeed");

    let error = AuthenticatedRouterAnnouncement::decode(&encoded)
        .expect_err("unsupported capability ids must be rejected");
    assert!(matches!(
        error,
        RouterAnnouncementError::PayloadMalformed("unsupported router capability id")
    ));
}

#[test]
fn trailing_bytes_after_capabilities_are_rejected_as_malformed_payload() {
    let identity = make_identity("router-a");
    let mut malformed_payload = encode_router_payload_raw(6, &[1]);
    malformed_payload.extend_from_slice(&[0xaa, 0xbb]);
    let message = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::RouterAnnouncement,
        malformed_payload,
    )
    .expect("lower-level signing should succeed");
    let encoded = message.encode().expect("encode should succeed");

    let error = AuthenticatedRouterAnnouncement::decode(&encoded)
        .expect_err("unexpected trailing bytes must be rejected");
    assert!(matches!(
        error,
        RouterAnnouncementError::PayloadMalformed(
            "unexpected trailing bytes in router announcement payload"
        )
    ));
}

#[test]
fn unsupported_or_truncated_router_payload_is_rejected() {
    let identity = make_identity("router-a");

    let unsupported = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::RouterAnnouncement,
        vec![0x7f, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
    )
    .expect("lower-level signing should succeed");
    let unsupported_error = AuthenticatedRouterAnnouncement::decode(
        &unsupported.encode().expect("encode should succeed"),
    )
    .expect_err("unsupported router payload version must be rejected");
    assert!(matches!(
        unsupported_error,
        RouterAnnouncementError::UnsupportedPayloadVersion(0x7f)
    ));

    let truncated = AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::RouterAnnouncement,
        vec![ROUTER_PAYLOAD_VERSION, 0, 0, 0],
    )
    .expect("lower-level signing should succeed");
    let truncated_error = AuthenticatedRouterAnnouncement::decode(
        &truncated.encode().expect("encode should succeed"),
    )
    .expect_err("truncated router payload must be rejected");
    assert!(matches!(
        truncated_error,
        RouterAnnouncementError::PayloadTruncated
    ));
}
