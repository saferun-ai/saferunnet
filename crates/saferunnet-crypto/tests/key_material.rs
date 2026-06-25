use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, PublicKey, SecretKey, Signature,
    SignedEnvelope,
};

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

    assert_eq!(pair.secret_key.algorithm(), KeyAlgorithm::Ed25519);
    assert_eq!(pair.public_key.algorithm(), KeyAlgorithm::Ed25519);
    assert_eq!(pair.secret_key.public_key(), pair.public_key);
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

#[test]
fn signature_round_trips_with_secret_and_public_key() {
    let generator = Ed25519KeyGenerator::new();
    let pair = generator.generate(KeyAlgorithm::Ed25519).unwrap();
    let message = b"saferunnet signing round trip";

    let signature = pair.secret_key.sign(message).unwrap();

    assert_eq!(signature.algorithm(), KeyAlgorithm::Ed25519);
    assert_eq!(signature.as_bytes().len(), 64);
    assert!(pair.public_key.verify(message, &signature).is_ok());
}

#[test]
fn verification_fails_for_wrong_message() {
    let generator = Ed25519KeyGenerator::new();
    let pair = generator.generate(KeyAlgorithm::Ed25519).unwrap();
    let signature = pair.secret_key.sign(b"original").unwrap();

    let error = pair.public_key.verify(b"tampered", &signature).unwrap_err();

    assert_eq!(error, saferunnet_crypto::SignatureError::VerificationFailed);
}

#[test]
fn verification_fails_for_wrong_public_key() {
    let generator = Ed25519KeyGenerator::new();
    let pair = generator.generate(KeyAlgorithm::Ed25519).unwrap();
    let other_pair = generator.generate(KeyAlgorithm::Ed25519).unwrap();
    let signature: Signature = pair.secret_key.sign(b"shared message").unwrap();

    let error = other_pair
        .public_key
        .verify(b"shared message", &signature)
        .unwrap_err();

    assert_eq!(error, saferunnet_crypto::SignatureError::VerificationFailed);
}

#[test]
fn verification_rejects_invalid_signature_material() {
    let generator = Ed25519KeyGenerator::new();
    let pair = generator.generate(KeyAlgorithm::Ed25519).unwrap();
    let invalid_signature = Signature::from_bytes(KeyAlgorithm::Ed25519, vec![0u8; 63]);

    let error = pair
        .public_key
        .verify(b"message", &invalid_signature)
        .unwrap_err();

    assert_eq!(
        error,
        saferunnet_crypto::SignatureError::InvalidSignatureMaterial
    );
}

#[test]
fn signed_envelope_sign_and_verify_round_trip() {
    let generator = Ed25519KeyGenerator::new();
    let pair = generator.generate(KeyAlgorithm::Ed25519).unwrap();
    let payload = b"protocol boundary payload".to_vec();

    let envelope = SignedEnvelope::signed(&pair.secret_key, payload.clone()).unwrap();

    assert_eq!(envelope.payload(), payload.as_slice());
    assert_eq!(envelope.signer(), &pair.public_key);
    assert_eq!(envelope.signature().algorithm(), KeyAlgorithm::Ed25519);
    assert!(envelope.verify().is_ok());
}

#[test]
fn signed_envelope_verification_fails_when_payload_tampered() {
    let generator = Ed25519KeyGenerator::new();
    let pair = generator.generate(KeyAlgorithm::Ed25519).unwrap();
    let envelope = SignedEnvelope::signed(&pair.secret_key, b"original".to_vec()).unwrap();

    let tampered = SignedEnvelope::from_parts(
        b"tampered".to_vec(),
        envelope.signer().clone(),
        envelope.signature().clone(),
    );

    let error = tampered.verify().unwrap_err();

    assert_eq!(error, saferunnet_crypto::SignatureError::VerificationFailed);
}

#[test]
fn signed_envelope_verification_fails_for_wrong_signer_signature_pairing() {
    let generator = Ed25519KeyGenerator::new();
    let pair_a = generator.generate(KeyAlgorithm::Ed25519).unwrap();
    let pair_b = generator.generate(KeyAlgorithm::Ed25519).unwrap();
    let payload = b"shared payload".to_vec();
    let envelope_a = SignedEnvelope::signed(&pair_a.secret_key, payload.clone()).unwrap();

    let mismatched =
        SignedEnvelope::from_parts(payload, pair_b.public_key, envelope_a.signature().clone());

    let error = mismatched.verify().unwrap_err();

    assert_eq!(error, saferunnet_crypto::SignatureError::VerificationFailed);
}

#[test]
fn signed_envelope_preserves_binary_payload_exactly() {
    let generator = Ed25519KeyGenerator::new();
    let pair = generator.generate(KeyAlgorithm::Ed25519).unwrap();
    let payload = vec![0x00, 0xff, 0x7f, 0x80, 0x0a, 0x00, 0xfe, 0x55];

    let envelope = SignedEnvelope::signed(&pair.secret_key, payload.clone()).unwrap();

    assert_eq!(envelope.payload(), payload.as_slice());
    assert!(envelope.verify().is_ok());
}

#[test]
fn signed_envelope_rejects_valid_message_when_expected_signer_differs() {
    let generator = Ed25519KeyGenerator::new();
    let pair_a = generator.generate(KeyAlgorithm::Ed25519).unwrap();
    let pair_b = generator.generate(KeyAlgorithm::Ed25519).unwrap();
    let envelope =
        SignedEnvelope::signed(&pair_b.secret_key, b"peer-bound payload".to_vec()).unwrap();

    let error = envelope.verify_signed_by(&pair_a.public_key).unwrap_err();

    assert_eq!(
        error,
        saferunnet_crypto::SignatureError::ExpectedSignerMismatch
    );
}
