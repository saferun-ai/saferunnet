use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator};
use saferunnet_identity::NodeIdentity;
use saferunnet_service::{AuthenticatedExitAnnounceMessage, ExitAnnounceError, ServiceMessageKind};

fn make_identity() -> NodeIdentity {
    let key_pair = Ed25519KeyGenerator::new()
        .generate(KeyAlgorithm::Ed25519)
        .expect("test key generation should succeed");
    NodeIdentity {
        nickname: "exit-test".into(),
        algorithm: KeyAlgorithm::Ed25519,
        secret_key: key_pair.secret_key,
        public_key: key_pair.public_key,
    }
}

#[test]
fn exit_announce_roundtrip() {
    let identity = make_identity();
    let exit_pk = identity.public_key.clone();
    let msg = AuthenticatedExitAnnounceMessage::sign(
        &identity,
        exit_pk,
        vec!["10.0.0.1:8080".into(), "exit.loki:443".into()],
    )
    .unwrap();
    let encoded = msg.encode().unwrap();
    let decoded = AuthenticatedExitAnnounceMessage::decode_verified(&encoded).unwrap();
    assert_eq!(decoded.addresses().len(), 2);
    assert_eq!(decoded.addresses()[0], "10.0.0.1:8080");
    assert_eq!(decoded.addresses()[1], "exit.loki:443");
}

#[test]
fn exit_announce_reject_empty_addresses() {
    let identity = make_identity();
    let result =
        AuthenticatedExitAnnounceMessage::sign(&identity, identity.public_key.clone(), vec![]);
    assert!(matches!(result, Err(ExitAnnounceError::EmptyAddresses)));
}

#[test]
fn exit_announce_reject_wrong_kind() {
    let identity = make_identity();
    let inner = saferunnet_service::AuthenticatedServiceMessage::sign(
        &identity,
        ServiceMessageKind::Announcement,
        vec![1, 2, 3],
    )
    .unwrap();
    let encoded = inner.encode().unwrap();
    let result = AuthenticatedExitAnnounceMessage::decode_verified(&encoded);
    assert!(matches!(result, Err(ExitAnnounceError::WrongKind)));
}

#[test]
fn exit_announce_reject_truncated() {
    let result = AuthenticatedExitAnnounceMessage::decode_verified(&[1, 2]);
    assert!(result.is_err());
}
