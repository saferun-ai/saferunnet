use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerationError, KeyGenerator, KeyPair, PublicKey,
    SecretKey, SignedEnvelope, SignedEnvelopeCodec,
};
use saferunnet_identity::{
    FileIdentityRepository, IdentityProof, IdentityProofError, IdentitySpec, NodeIdentity,
};
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::process::Command;

fn temp_path() -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("saferunnet-identity-{unique}.txt"))
}

fn generated_identity(nickname: &str) -> NodeIdentity {
    let key_pair = Ed25519KeyGenerator::new()
        .generate(KeyAlgorithm::Ed25519)
        .unwrap();
    NodeIdentity {
        nickname: nickname.to_string(),
        algorithm: KeyAlgorithm::Ed25519,
        secret_key: key_pair.secret_key,
        public_key: key_pair.public_key,
    }
}

#[test]
fn file_repository_round_trips_identity() {
    let path = temp_path();
    let repo = FileIdentityRepository::new(path.clone());
    let identity = NodeIdentity {
        nickname: "edge-node".to_string(),
        algorithm: KeyAlgorithm::Ed25519,
        secret_key: SecretKey::from_hex(
            KeyAlgorithm::Ed25519,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap(),
        public_key: PublicKey::from_hex(
            KeyAlgorithm::Ed25519,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap(),
    };

    repo.save(&identity).unwrap();
    let loaded = repo.load().unwrap();

    assert_eq!(loaded.nickname, "edge-node");
    assert_eq!(loaded.algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(loaded.secret_key.to_hex(), identity.secret_key.to_hex());
    assert_eq!(loaded.public_key.to_hex(), identity.public_key.to_hex());

    let _ = fs::remove_file(path);
}

#[test]
fn file_repository_rejects_missing_fields() {
    let path = temp_path();
    fs::write(&path, "nickname=edge\nalgorithm=ed25519\n").unwrap();

    let repo = FileIdentityRepository::new(path.clone());
    let error = repo.load().unwrap_err();

    assert!(error.to_string().contains("secret_key"));
    let _ = fs::remove_file(path);
}

struct RecordingGenerator {
    calls: Arc<Mutex<u8>>,
}

impl KeyGenerator for RecordingGenerator {
    fn generate(&self, algorithm: KeyAlgorithm) -> Result<KeyPair, KeyGenerationError> {
        *self.calls.lock().unwrap() += 1;
        assert_eq!(algorithm, KeyAlgorithm::Ed25519);

        Ok(KeyPair {
            secret_key: SecretKey::from_hex(
                KeyAlgorithm::Ed25519,
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )
            .unwrap(),
            public_key: PublicKey::from_hex(
                KeyAlgorithm::Ed25519,
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            )
            .unwrap(),
        })
    }
}

#[test]
fn file_repository_bootstraps_a_missing_identity_once() {
    let path = temp_path();
    let repo = FileIdentityRepository::new(path.clone());
    let calls = Arc::new(Mutex::new(0));
    let generator = RecordingGenerator {
        calls: calls.clone(),
    };
    let spec = IdentitySpec {
        nickname: "bootstrap-node".to_string(),
        algorithm: KeyAlgorithm::Ed25519,
    };

    let created = repo.load_or_create(&spec, &generator).unwrap();
    let loaded_again = repo.load_or_create(&spec, &generator).unwrap();

    assert_eq!(created.nickname, "bootstrap-node");
    assert_eq!(created.algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(
        created.secret_key.to_hex(),
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    );
    assert_eq!(
        created.public_key.to_hex(),
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    );
    assert_eq!(loaded_again, created);
    assert_eq!(*calls.lock().unwrap(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn file_repository_bootstraps_with_the_real_ed25519_generator() {
    let path = temp_path();
    let repo = FileIdentityRepository::new(path.clone());
    let spec = IdentitySpec {
        nickname: "real-generator-node".to_string(),
        algorithm: KeyAlgorithm::Ed25519,
    };

    let created = repo
        .load_or_create(&spec, &Ed25519KeyGenerator::new())
        .unwrap();
    let loaded = repo.load().unwrap();

    assert_eq!(loaded, created);
    assert_eq!(created.nickname, "real-generator-node");
    assert_eq!(created.algorithm, KeyAlgorithm::Ed25519);

    let _ = fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn file_repository_writes_private_permissions_for_identity_files() {
    let path = temp_path();
    let repo = FileIdentityRepository::new(path.clone());
    let identity = NodeIdentity {
        nickname: "locked-down-node".to_string(),
        algorithm: KeyAlgorithm::Ed25519,
        secret_key: SecretKey::from_hex(
            KeyAlgorithm::Ed25519,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap(),
        public_key: PublicKey::from_hex(
            KeyAlgorithm::Ed25519,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap(),
    };

    repo.save(&identity).unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let _ = fs::remove_file(path);
}

#[cfg(windows)]
#[test]
fn file_repository_writes_protected_acl_for_identity_files() {
    let path = temp_path();
    let repo = FileIdentityRepository::new(path.clone());
    let identity = NodeIdentity {
        nickname: "locked-down-node".to_string(),
        algorithm: KeyAlgorithm::Ed25519,
        secret_key: SecretKey::from_hex(
            KeyAlgorithm::Ed25519,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap(),
        public_key: PublicKey::from_hex(
            KeyAlgorithm::Ed25519,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap(),
    };

    repo.save(&identity).unwrap();

    let output = Command::new("icacls.exe").arg(&path).output().unwrap();
    let acl = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "icacls failed: stdout={acl:?} stderr={stderr:?}"
    );
    assert!(acl.contains("NT AUTHORITY\\SYSTEM:(F)"), "acl was {acl:?}");
    assert!(
        acl.contains("BUILTIN\\Administrators:(F)"),
        "acl was {acl:?}"
    );
    assert!(acl.contains("OWNER RIGHTS:(F)"), "acl was {acl:?}");
    assert!(!acl.contains("Everyone:"), "acl was {acl:?}");

    let _ = fs::remove_file(path);
}

#[test]
fn identity_proof_sign_and_verify_round_trip() {
    let identity = generated_identity("proof-node");
    let proof = IdentityProof::sign(&identity).unwrap();

    proof.verify().unwrap();
    assert_eq!(proof.claim().nickname, "proof-node");
    assert_eq!(proof.claim().algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(proof.claim().public_key, identity.public_key);
}

#[test]
fn identity_proof_sign_rejects_mismatched_identity_keypair() {
    let mut identity = generated_identity("mismatched-keypair-node");
    let other_identity = generated_identity("other-node");
    identity.public_key = other_identity.public_key;

    let error = IdentityProof::sign(&identity).unwrap_err();

    assert!(matches!(error, IdentityProofError::KeyPairMismatch));
}

#[test]
fn identity_proof_encode_decode_round_trip_preserves_claim_and_verifies() {
    let identity = generated_identity("codec-node");
    let proof = IdentityProof::sign(&identity).unwrap();
    let encoded = proof.encode().unwrap();

    let decoded = IdentityProof::decode(&encoded).unwrap();

    assert_eq!(decoded.claim(), proof.claim());
    decoded.verify().unwrap();
}

#[test]
fn identity_proof_decode_verified_round_trip_preserves_claim() {
    let identity = generated_identity("decode-verified-node");
    let proof = IdentityProof::sign(&identity).unwrap();
    let encoded = proof.encode().unwrap();

    let decoded = IdentityProof::decode_verified(&encoded).unwrap();

    assert_eq!(decoded.claim(), proof.claim());
}

#[test]
fn identity_proof_tampered_payload_fails_verification_after_decode() {
    let identity = generated_identity("tamper-node");
    let proof = IdentityProof::sign(&identity).unwrap();
    let encoded = proof.encode().unwrap();
    let envelope = SignedEnvelopeCodec::decode(&encoded).unwrap();
    let mut tampered_payload = envelope.payload().to_vec();
    tampered_payload[3] ^= 0x01;
    let tampered_envelope = SignedEnvelope::from_parts(
        tampered_payload,
        envelope.signer().clone(),
        envelope.signature().clone(),
    );
    let tampered_bytes = SignedEnvelopeCodec::encode(&tampered_envelope).unwrap();

    let decoded = IdentityProof::decode(&tampered_bytes).unwrap();

    assert!(matches!(
        decoded.verify(),
        Err(IdentityProofError::Signature(_))
    ));
}

#[test]
fn identity_proof_decode_rejects_malformed_claim_payload() {
    let identity = generated_identity("malformed-node");
    let proof = IdentityProof::sign(&identity).unwrap();
    let encoded = proof.encode().unwrap();
    let envelope = SignedEnvelopeCodec::decode(&encoded).unwrap();
    let mut malformed_payload = envelope.payload().to_vec();
    malformed_payload[0] = 42;
    let malformed_envelope = SignedEnvelope::from_parts(
        malformed_payload,
        envelope.signer().clone(),
        envelope.signature().clone(),
    );
    let malformed_bytes = SignedEnvelopeCodec::encode(&malformed_envelope).unwrap();

    let error = IdentityProof::decode(&malformed_bytes).unwrap_err();

    assert!(matches!(
        error,
        IdentityProofError::ClaimPayloadMalformed(_)
    ));
}

#[test]
fn identity_proof_verify_rejects_mismatched_claimed_public_key() {
    let identity = generated_identity("mismatch-node");
    let proof = IdentityProof::sign(&identity).unwrap();
    let encoded = proof.encode().unwrap();
    let envelope = SignedEnvelopeCodec::decode(&encoded).unwrap();
    let mut tampered_payload = envelope.payload().to_vec();
    let public_key_offset = 4 + identity.nickname.len() + 1;
    tampered_payload[public_key_offset] ^= 0x01;
    let tampered_envelope = SignedEnvelope::from_parts(
        tampered_payload,
        envelope.signer().clone(),
        envelope.signature().clone(),
    );
    let tampered_bytes = SignedEnvelopeCodec::encode(&tampered_envelope).unwrap();
    let decoded = IdentityProof::decode(&tampered_bytes).unwrap();

    assert!(matches!(
        decoded.verify(),
        Err(IdentityProofError::ClaimedSignerMismatch)
    ));
}
