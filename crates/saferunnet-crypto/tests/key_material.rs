use saferunnet_crypto::{KeyAlgorithm, PublicKey, SecretKey};

#[test]
fn public_key_hex_round_trips() {
    let original = PublicKey::from_hex(
        KeyAlgorithm::Ed25519,
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    )
    .unwrap();

    assert_eq!(
        original.to_hex(),
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    );
}

#[test]
fn secret_key_hex_rejects_wrong_length() {
    let error = SecretKey::from_hex(KeyAlgorithm::Ed25519, "abcd").unwrap_err();
    assert!(error.to_string().contains("64 hex characters"));
}
