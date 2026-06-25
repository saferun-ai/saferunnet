use ed25519_dalek::SigningKey;
use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, PublicKey, SecretKey};

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

#[test]
fn public_and_secret_keys_round_trip_through_bytes() {
    let secret = SecretKey::from_bytes(KeyAlgorithm::Ed25519, [0x11; 32]);
    let public = PublicKey::from_bytes(KeyAlgorithm::Ed25519, [0x22; 32]);

    assert_eq!(secret.to_bytes(), [0x11; 32]);
    assert_eq!(public.to_bytes(), [0x22; 32]);
}

#[test]
fn ed25519_generator_produces_a_consistent_keypair() {
    let generator = Ed25519KeyGenerator::new();
    let pair = generator.generate(KeyAlgorithm::Ed25519).unwrap();

    let signing_key = SigningKey::from_bytes(&pair.secret_key.to_bytes());

    assert_eq!(pair.secret_key.algorithm(), KeyAlgorithm::Ed25519);
    assert_eq!(pair.public_key.algorithm(), KeyAlgorithm::Ed25519);
    assert_eq!(
        signing_key.verifying_key().to_bytes(),
        pair.public_key.to_bytes()
    );
}

#[test]
fn secret_key_debug_output_is_redacted() {
    let secret = SecretKey::from_bytes(KeyAlgorithm::Ed25519, [0x11; 32]);
    let debug = format!("{secret:?}");

    assert!(debug.contains("SecretKey"));
    assert!(!debug.contains("17"));
}

#[test]
fn key_material_can_append_hex_into_an_existing_string() {
    let secret = SecretKey::from_hex(
        KeyAlgorithm::Ed25519,
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    )
    .unwrap();
    let public = PublicKey::from_hex(
        KeyAlgorithm::Ed25519,
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    )
    .unwrap();
    let mut output = String::from("prefix:");

    secret.write_hex(&mut output);
    output.push('|');
    public.write_hex(&mut output);

    assert_eq!(
        output,
        "prefix:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20|202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    );
}
