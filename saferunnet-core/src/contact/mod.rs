use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use saferunnet_crypto::{
    EnvelopeCodecError, KeyAlgorithm, KeyGenerationError, KeyGenerator, KeyMaterialError, KeyPair,
    PublicKey, SecretKey, SignatureError, SignedEnvelope, SignedEnvelopeCodec,
};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    pub nickname: String,
    pub algorithm: KeyAlgorithm,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySpec {
    pub nickname: String,
    pub algorithm: KeyAlgorithm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityClaim {
    pub nickname: String,
    pub algorithm: KeyAlgorithm,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProof {
    claim: IdentityClaim,
    envelope: SignedEnvelope,
}

impl IdentityProof {
    pub fn sign(identity: &NodeIdentity) -> Result<Self, IdentityProofError> {
        if identity.secret_key.public_key() != identity.public_key {
            return Err(IdentityProofError::KeyPairMismatch);
        }
        let claim = IdentityClaim {
            nickname: identity.nickname.clone(),
            algorithm: identity.algorithm,
            public_key: identity.public_key.clone(),
        };
        let payload = encode_claim_payload(&claim)?;
        let envelope = SignedEnvelope::signed(&identity.secret_key, payload)?;
        Ok(Self { claim, envelope })
    }

    pub fn encode(&self) -> Result<Vec<u8>, IdentityProofError> {
        SignedEnvelopeCodec::encode(&self.envelope).map_err(IdentityProofError::from)
    }

    pub fn decode(input: &[u8]) -> Result<Self, IdentityProofError> {
        let envelope = SignedEnvelopeCodec::decode(input)?;
        let claim = decode_claim_payload(envelope.payload())?;
        Ok(Self { claim, envelope })
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, IdentityProofError> {
        let proof = Self::decode(input)?;
        proof.verify()?;
        Ok(proof)
    }

    pub fn claim(&self) -> &IdentityClaim {
        &self.claim
    }

    pub fn envelope(&self) -> &SignedEnvelope {
        &self.envelope
    }

    pub fn verify(&self) -> Result<(), IdentityProofError> {
        let signed_claim = decode_claim_payload(self.envelope.payload())?;
        if signed_claim != self.claim {
            return Err(IdentityProofError::ClaimPayloadMismatch);
        }
        if self.claim.algorithm != self.claim.public_key.algorithm() {
            return Err(IdentityProofError::ClaimAlgorithmMismatch);
        }
        self.envelope
            .verify_signed_by(&self.claim.public_key)
            .map_err(|error| match error {
                SignatureError::ExpectedSignerMismatch => IdentityProofError::ClaimedSignerMismatch,
                other => IdentityProofError::Signature(other),
            })
    }
}

#[derive(Debug, Error)]
pub enum IdentityProofError {
    #[error(transparent)]
    Signature(#[from] SignatureError),
    #[error(transparent)]
    EnvelopeCodec(#[from] EnvelopeCodecError),
    #[error("identity claim payload truncated")]
    ClaimPayloadTruncated,
    #[error("identity claim payload malformed: {0}")]
    ClaimPayloadMalformed(&'static str),
    #[error("identity claim algorithm does not match claim public key algorithm")]
    ClaimAlgorithmMismatch,
    #[error("identity claim metadata does not match signed payload")]
    ClaimPayloadMismatch,
    #[error("identity claim public key does not match envelope signer")]
    ClaimedSignerMismatch,
    #[error("node identity secret/public keypair mismatch")]
    KeyPairMismatch,
    #[error(
        "identity claim field `{field}` exceeds encoded limit `{max}` with length `{length}` bytes"
    )]
    ClaimLengthOverflow {
        field: &'static str,
        length: usize,
        max: usize,
    },
}

pub struct FileIdentityRepository {
    path: PathBuf,
}

impl FileIdentityRepository {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn save(&self, identity: &NodeIdentity) -> Result<(), IdentityRepositoryError> {
        let mut contents = Zeroizing::new(String::new());
        use std::fmt::Write as _;

        let _ = write!(
            &mut *contents,
            "nickname={}\nalgorithm={}\nsecret_key=",
            identity.nickname,
            identity.algorithm.as_str(),
        );
        identity.secret_key.write_hex(&mut contents);
        contents.push_str("\npublic_key=");
        identity.public_key.write_hex(&mut contents);
        contents.push('\n');

        write_identity_file(&self.path, &contents)
    }

    pub fn load(&self) -> Result<NodeIdentity, IdentityRepositoryError> {
        let contents = std::fs::read_to_string(&self.path).map_err(|source| {
            IdentityRepositoryError::Read {
                path: self.path.display().to_string(),
                source,
            }
        })?;
        parse_identity(&contents)
    }

    pub fn load_or_create(
        &self,
        spec: &IdentitySpec,
        generator: &dyn KeyGenerator,
    ) -> Result<NodeIdentity, IdentityRepositoryError> {
        match self.load() {
            Ok(identity) => Ok(identity),
            Err(IdentityRepositoryError::Read { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                let generated = generator.generate(spec.algorithm)?;
                let identity = build_identity(spec, generated);
                self.save(&identity)?;
                Ok(identity)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug, Error)]
pub enum IdentityRepositoryError {
    #[error("failed to read identity file `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write identity file `{path}`: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("missing required identity field `{0}`")]
    MissingField(&'static str),
    #[error(transparent)]
    KeyMaterial(#[from] KeyMaterialError),
    #[error(transparent)]
    KeyGeneration(#[from] KeyGenerationError),
    #[error("invalid algorithm: {0}")]
    InvalidAlgorithm(String),
}

fn build_identity(spec: &IdentitySpec, key_pair: KeyPair) -> NodeIdentity {
    NodeIdentity {
        nickname: spec.nickname.clone(),
        algorithm: spec.algorithm,
        secret_key: key_pair.secret_key,
        public_key: key_pair.public_key,
    }
}

fn write_identity_file(path: &Path, contents: &str) -> Result<(), IdentityRepositoryError> {
    if path.exists() {
        write_with_replace(path, contents)
    } else {
        write_new_secure_file(path, contents)
    }
}

fn write_new_secure_file(path: &Path, contents: &str) -> Result<(), IdentityRepositoryError> {
    let mut file = new_secure_file(path)?;
    file.write_all(contents.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|source| IdentityRepositoryError::Write {
            path: path.display().to_string(),
            source,
        })
}

fn write_with_replace(path: &Path, contents: &str) -> Result<(), IdentityRepositoryError> {
    let temp_path = temp_write_path(path);
    write_new_secure_file(&temp_path, contents)?;

    if let Err(error) = replace_file(path, &temp_path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(error);
    }

    Ok(())
}

fn temp_write_path(path: &Path) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_extension(format!("tmp.{unique}"))
}

#[cfg(unix)]
fn new_secure_file(path: &Path) -> Result<std::fs::File, IdentityRepositoryError> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| IdentityRepositoryError::Write {
            path: path.display().to_string(),
            source,
        })
}

#[cfg(windows)]
fn new_secure_file(path: &Path) -> Result<std::fs::File, IdentityRepositoryError> {
    use std::ffi::OsStr;
    use std::mem::size_of;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_SEQUENTIAL_SCAN,
        FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_WRITE,
    };

    const OWNER_ONLY_FILE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)";

    let mut security_descriptor = std::ptr::null_mut();
    let sddl = wide_null(OsStr::new(OWNER_ONLY_FILE_SDDL));
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut security_descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(IdentityRepositoryError::Write {
            path: path.display().to_string(),
            source: std::io::Error::last_os_error(),
        });
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor,
        bInheritHandle: 0,
    };
    let path_wide = wide_null(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            FILE_GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_SEQUENTIAL_SCAN,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(security_descriptor);
    }
    if handle == INVALID_HANDLE_VALUE {
        return Err(IdentityRepositoryError::Write {
            path: path.display().to_string(),
            source: std::io::Error::last_os_error(),
        });
    }

    Ok(unsafe { std::fs::File::from_raw_handle(handle as _) })
}

#[cfg(all(not(unix), not(windows)))]
fn new_secure_file(path: &Path) -> Result<std::fs::File, IdentityRepositoryError> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| IdentityRepositoryError::Write {
            path: path.display().to_string(),
            source,
        })
}

#[cfg(windows)]
fn replace_file(path: &Path, temp_path: &Path) -> Result<(), IdentityRepositoryError> {
    use windows_sys::Win32::Storage::FileSystem::{REPLACEFILE_WRITE_THROUGH, ReplaceFileW};

    let path_wide = wide_null(path.as_os_str());
    let temp_wide = wide_null(temp_path.as_os_str());
    let replaced = unsafe {
        ReplaceFileW(
            path_wide.as_ptr(),
            temp_wide.as_ptr(),
            std::ptr::null(),
            REPLACEFILE_WRITE_THROUGH,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if replaced == 0 {
        return Err(IdentityRepositoryError::Write {
            path: path.display().to_string(),
            source: std::io::Error::last_os_error(),
        });
    }

    Ok(())
}

#[cfg(not(windows))]
fn replace_file(path: &Path, temp_path: &Path) -> Result<(), IdentityRepositoryError> {
    std::fs::rename(temp_path, path).map_err(|source| IdentityRepositoryError::Write {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(windows)]
fn wide_null(value: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn parse_identity(contents: &str) -> Result<NodeIdentity, IdentityRepositoryError> {
    let mut fields = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            fields.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    let nickname = fields
        .get("nickname")
        .cloned()
        .ok_or(IdentityRepositoryError::MissingField("nickname"))?;
    let algorithm_text = fields
        .get("algorithm")
        .cloned()
        .ok_or(IdentityRepositoryError::MissingField("algorithm"))?;
    let algorithm = KeyAlgorithm::from_str(&algorithm_text)
        .map_err(|_| IdentityRepositoryError::InvalidAlgorithm(algorithm_text.clone()))?;
    let secret_key = SecretKey::from_hex(
        algorithm,
        fields
            .get("secret_key")
            .ok_or(IdentityRepositoryError::MissingField("secret_key"))?,
    )?;
    let public_key = PublicKey::from_hex(
        algorithm,
        fields
            .get("public_key")
            .ok_or(IdentityRepositoryError::MissingField("public_key"))?,
    )?;

    Ok(NodeIdentity {
        nickname,
        algorithm,
        secret_key,
        public_key,
    })
}

const IDENTITY_CLAIM_VERSION: u8 = 1;

fn encode_claim_payload(claim: &IdentityClaim) -> Result<Vec<u8>, IdentityProofError> {
    let nickname_bytes = claim.nickname.as_bytes();
    let nickname_len = u16::try_from(nickname_bytes.len()).map_err(|_| {
        IdentityProofError::ClaimLengthOverflow {
            field: "nickname",
            length: nickname_bytes.len(),
            max: u16::MAX as usize,
        }
    })?;
    let public_key_bytes = claim.public_key.to_bytes();
    let mut payload = Vec::with_capacity(1 + 2 + nickname_bytes.len() + 1 + public_key_bytes.len());
    payload.push(IDENTITY_CLAIM_VERSION);
    payload.extend_from_slice(&nickname_len.to_be_bytes());
    payload.extend_from_slice(nickname_bytes);
    payload.push(encode_claim_algorithm(claim.algorithm));
    payload.extend_from_slice(&public_key_bytes);
    Ok(payload)
}

fn decode_claim_payload(input: &[u8]) -> Result<IdentityClaim, IdentityProofError> {
    let mut cursor = input;
    let version = take_claim_exact(&mut cursor, 1)?[0];
    if version != IDENTITY_CLAIM_VERSION {
        return Err(IdentityProofError::ClaimPayloadMalformed(
            "unsupported identity claim version",
        ));
    }

    let nickname_len = u16::from_be_bytes(
        take_claim_exact(&mut cursor, 2)?
            .try_into()
            .expect("take_claim_exact guarantees exact byte count"),
    ) as usize;
    let nickname_bytes = take_claim_exact(&mut cursor, nickname_len)?;
    let nickname = std::str::from_utf8(nickname_bytes)
        .map_err(|_| IdentityProofError::ClaimPayloadMalformed("nickname is not valid UTF-8"))?
        .to_string();
    let algorithm = decode_claim_algorithm(take_claim_exact(&mut cursor, 1)?[0])?;
    let public_key_bytes: [u8; 32] = take_claim_exact(&mut cursor, 32)?
        .try_into()
        .expect("take_claim_exact guarantees exact byte count");

    if !cursor.is_empty() {
        return Err(IdentityProofError::ClaimPayloadMalformed(
            "unexpected trailing bytes in identity claim payload",
        ));
    }

    Ok(IdentityClaim {
        nickname,
        algorithm,
        public_key: PublicKey::from_bytes(algorithm, public_key_bytes),
    })
}

fn take_claim_exact<'a>(
    input: &mut &'a [u8],
    count: usize,
) -> Result<&'a [u8], IdentityProofError> {
    if input.len() < count {
        return Err(IdentityProofError::ClaimPayloadTruncated);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}

fn encode_claim_algorithm(algorithm: KeyAlgorithm) -> u8 {
    match algorithm {
        KeyAlgorithm::Ed25519 => 1,
    }
}

fn decode_claim_algorithm(encoded: u8) -> Result<KeyAlgorithm, IdentityProofError> {
    match encoded {
        1 => Ok(KeyAlgorithm::Ed25519),
        _ => Err(IdentityProofError::ClaimPayloadMalformed(
            "unsupported identity claim algorithm id",
        )),
    }
}
