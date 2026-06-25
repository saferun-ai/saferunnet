use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerationError, KeyGenerator, KeyPair, PublicKey,
    SecretKey,
};
use saferunnet_identity::{FileIdentityRepository, IdentitySpec, NodeIdentity};
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
