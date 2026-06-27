use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator};
use saferunnet_service::SessionTag;
use saferunnet_transport::{LinkHandshake, LinkSession, SessionState};

#[test]
fn link_session_full_lifecycle() {
    let pk_bytes = [0x42u8; 32];
    let pk = saferunnet_crypto::PublicKey::from_bytes(
        saferunnet_crypto::KeyAlgorithm::Ed25519,
        pk_bytes,
    );
    let mut session = LinkSession::new(SessionTag::new(42), pk, 1000);

    assert_eq!(session.state, SessionState::Initiating);
    assert!(!session.is_active());

    session.accept().unwrap();
    assert!(session.is_active());

    session.switch_path().unwrap();
    session.complete_switch().unwrap();
    assert!(session.is_active());

    session.close().unwrap();
    assert!(!session.is_active());
}

#[test]
fn link_session_rejects_invalid_transitions() {
    let pk_bytes = [0x42u8; 32];
    let pk = saferunnet_crypto::PublicKey::from_bytes(
        saferunnet_crypto::KeyAlgorithm::Ed25519,
        pk_bytes,
    );
    let mut session = LinkSession::new(SessionTag::new(7), pk, 0);

    // Cannot switch before accept
    let result = session.switch_path();
    assert!(result.is_err());

    // Accept works
    session.accept().unwrap();

    // Cannot accept again
    let result = session.accept();
    assert!(result.is_err());
}

#[test]
fn handshake_produces_directional_keys() {
    let keygen = Ed25519KeyGenerator::new();
    let kp = keygen
        .generate(KeyAlgorithm::Ed25519)
        .expect("test key generation should succeed");

    let init = LinkHandshake::initiate(&kp.public_key.to_bytes()).expect("initiate handshake");

    let resp =
        LinkHandshake::respond(&kp.secret_key, &init.ephemeral_public).expect("respond handshake");

    // Both sides produce valid 32-byte keys
    assert_eq!(init.send_key.len(), 32);
    assert_eq!(init.recv_key.len(), 32);
    assert_eq!(resp.send_key.len(), 32);
    assert_eq!(resp.recv_key.len(), 32);

    // Keys within each side are different
    assert_ne!(init.send_key.as_slice(), init.recv_key.as_slice());
    assert_ne!(resp.send_key.as_slice(), resp.recv_key.as_slice());
}
