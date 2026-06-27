use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, PublicKey, SignatureError, SignedEnvelope,
    SignedEnvelopeCodec,
};
use saferunnet_identity::{IdentityProof, NodeIdentity};
use saferunnet_service::{
    AddressFamily, AuthenticatedDhtIntroMessage, DhtIntroEntry, DhtIntroError, DhtIntroMessage,
    ServiceMessageKind,
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

fn make_test_entry(seed: u8) -> DhtIntroEntry {
    let mut pk_bytes = [0u8; 32];
    pk_bytes[0] = seed;
    pk_bytes[31] = seed;
    DhtIntroEntry {
        public_key: PublicKey::from_bytes(KeyAlgorithm::Ed25519, pk_bytes),
        family: AddressFamily::Ipv4,
        port: (seed as u16) * 100 + 1,
    }
}

fn encode_top_frame(proof: &IdentityProof, envelope: &SignedEnvelope) -> Vec<u8> {
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

#[test]
fn sign_and_verify_round_trip() {
    let identity = make_identity("alice");
    let payload = DhtIntroMessage {
        entries: vec![make_test_entry(1)],
    };
    let signed = AuthenticatedDhtIntroMessage::sign(&identity, payload.clone())
        .expect("sign should succeed");

    assert_eq!(signed.payload(), &payload);
    assert_eq!(
        signed.service_message().kind(),
        ServiceMessageKind::DhtIntro
    );
    signed.verify().expect("verify should succeed");
}

#[test]
fn encode_and_decode_round_trip() {
    let identity = make_identity("alice");
    let entries = vec![make_test_entry(1), make_test_entry(2), make_test_entry(3)];
    let payload = DhtIntroMessage {
        entries: entries.clone(),
    };
    let signed = AuthenticatedDhtIntroMessage::sign(&identity, payload.clone())
        .expect("sign should succeed");

    let encoded = signed.encode().expect("encode should succeed");
    let decoded = AuthenticatedDhtIntroMessage::decode(&encoded).expect("decode should succeed");

    assert_eq!(decoded.payload(), &payload);
    decoded.verify().expect("decoded message should verify");
}

#[test]
fn reject_wrong_service_kind() {
    let identity = make_identity("alice");
    let wrong_kind = saferunnet_service::AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        vec![
            1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 1, 0, 1,
        ],
    )
    .expect("sign should succeed");

    let encoded = wrong_kind.encode().expect("encode should succeed");
    let error = AuthenticatedDhtIntroMessage::decode(&encoded)
        .expect_err("unexpected service kind should be rejected");

    assert!(matches!(error, DhtIntroError::Service(_)));
}

#[test]
fn reject_tampered_payload() {
    let identity = make_identity("alice");
    let payload = DhtIntroMessage {
        entries: vec![make_test_entry(9)],
    };
    let signed =
        AuthenticatedDhtIntroMessage::sign(&identity, payload).expect("sign should succeed");

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

    let decoded = AuthenticatedDhtIntroMessage::decode_unverified(&encoded)
        .expect("unverified decode should parse framing and payload");
    let verify_error = decoded
        .verify()
        .expect_err("verify should fail for tampered signed payload");
    assert!(matches!(
        verify_error,
        DhtIntroError::Service(saferunnet_service::ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));

    let error = AuthenticatedDhtIntroMessage::decode(&encoded)
        .expect_err("decode should reject payload tampering");
    assert!(matches!(
        error,
        DhtIntroError::Service(saferunnet_service::ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}

#[test]
fn reject_empty_entries() {
    let identity = make_identity("alice");
    let payload = DhtIntroMessage { entries: vec![] };

    let error = AuthenticatedDhtIntroMessage::sign(&identity, payload)
        .expect_err("empty entries should be rejected at sign time");
    assert!(matches!(error, DhtIntroError::Empty));
}

#[test]
fn reject_too_many_entries() {
    let identity = make_identity("alice");
    let entries: Vec<DhtIntroEntry> = (0..9).map(make_test_entry).collect();
    let payload = DhtIntroMessage { entries };

    let error = AuthenticatedDhtIntroMessage::sign(&identity, payload)
        .expect_err("too many entries should be rejected at sign time");
    assert!(matches!(error, DhtIntroError::TooMany { max: 8, found: 9 }));
}

#[test]
fn reject_unsupported_version() {
    let identity = make_identity("alice");
    let mut body = vec![0x7f, 1];
    let test_entry = make_test_entry(1);
    body.extend_from_slice(&test_entry.public_key.to_bytes());
    body.push(1);
    body.extend_from_slice(&test_entry.port.to_be_bytes());

    let service = saferunnet_service::AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::DhtIntro,
        body,
    )
    .expect("sign should succeed");

    let encoded = service.encode().expect("encode should succeed");
    let error = AuthenticatedDhtIntroMessage::decode(&encoded)
        .expect_err("unsupported version should be rejected");
    assert!(matches!(error, DhtIntroError::UnsupportedVersion(0x7f)));
}

#[test]
fn reject_truncated() {
    let identity = make_identity("alice");
    let mut body = vec![1, 2];
    let test_entry = make_test_entry(1);
    body.extend_from_slice(&test_entry.public_key.to_bytes());
    body.push(1);
    body.extend_from_slice(&test_entry.port.to_be_bytes());

    let service = saferunnet_service::AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::DhtIntro,
        body,
    )
    .expect("sign should succeed");

    let encoded = service.encode().expect("encode should succeed");
    let error = AuthenticatedDhtIntroMessage::decode(&encoded)
        .expect_err("truncated payload should be rejected");
    assert!(matches!(error, DhtIntroError::PayloadTruncated));
}

#[test]
fn reject_trailing_bytes() {
    let identity = make_identity("alice");
    let mut body = vec![1, 1];
    let test_entry = make_test_entry(1);
    body.extend_from_slice(&test_entry.public_key.to_bytes());
    body.push(1);
    body.extend_from_slice(&test_entry.port.to_be_bytes());
    body.push(0xaa);

    let service = saferunnet_service::AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::DhtIntro,
        body,
    )
    .expect("sign should succeed");

    let encoded = service.encode().expect("encode should succeed");
    let error = AuthenticatedDhtIntroMessage::decode(&encoded)
        .expect_err("trailing bytes should be rejected");
    assert!(matches!(error, DhtIntroError::PayloadMalformed(_)));
}

#[test]
fn preserve_entry_ordering() {
    let identity = make_identity("alice");
    let entries: Vec<DhtIntroEntry> = (1..=5).map(make_test_entry).collect();
    let payload = DhtIntroMessage {
        entries: entries.clone(),
    };
    let signed =
        AuthenticatedDhtIntroMessage::sign(&identity, payload).expect("sign should succeed");

    let encoded = signed.encode().expect("encode should succeed");
    let decoded = AuthenticatedDhtIntroMessage::decode(&encoded).expect("decode should succeed");

    assert_eq!(decoded.payload().entries.len(), 5);
    for (i, entry) in decoded.payload().entries.iter().enumerate() {
        let expected = make_test_entry((i + 1) as u8);
        assert_eq!(entry.public_key, expected.public_key);
        assert_eq!(entry.family, expected.family);
        assert_eq!(entry.port, expected.port);
    }
}
