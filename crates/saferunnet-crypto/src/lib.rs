use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Ed25519,
}

impl KeyAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
        }
    }
}

impl std::str::FromStr for KeyAlgorithm {
    type Err = KeyMaterialError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ed25519" => Ok(Self::Ed25519),
            _ => Err(KeyMaterialError::UnsupportedAlgorithm(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

pub trait KeyGenerator: Send + Sync {
    fn generate(&self, algorithm: KeyAlgorithm) -> Result<KeyPair, KeyGenerationError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519KeyGenerator;

impl Ed25519KeyGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl KeyGenerator for Ed25519KeyGenerator {
    fn generate(&self, algorithm: KeyAlgorithm) -> Result<KeyPair, KeyGenerationError> {
        match algorithm {
            KeyAlgorithm::Ed25519 => {
                let mut csprng = rand_core::OsRng;
                let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);

                Ok(KeyPair {
                    secret_key: SecretKey::from_bytes(
                        KeyAlgorithm::Ed25519,
                        signing_key.to_bytes(),
                    ),
                    public_key: PublicKey::from_bytes(
                        KeyAlgorithm::Ed25519,
                        signing_key.verifying_key().to_bytes(),
                    ),
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    algorithm: KeyAlgorithm,
    bytes: [u8; 32],
}

impl PublicKey {
    pub fn from_bytes(algorithm: KeyAlgorithm, bytes: [u8; 32]) -> Self {
        Self { algorithm, bytes }
    }

    pub fn from_hex(algorithm: KeyAlgorithm, value: &str) -> Result<Self, KeyMaterialError> {
        Ok(Self {
            algorithm,
            bytes: decode_hex_32(value)?,
        })
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn write_hex(&self, output: &mut String) {
        encode_hex_into(&self.bytes, output);
    }

    pub fn to_hex(&self) -> String {
        encode_hex(&self.bytes)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        if self.algorithm != signature.algorithm {
            return Err(SignatureError::AlgorithmMismatch {
                key: self.algorithm,
                signature: signature.algorithm,
            });
        }

        match self.algorithm {
            KeyAlgorithm::Ed25519 => {
                let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&self.bytes)
                    .map_err(|_| SignatureError::InvalidKeyMaterial)?;
                let signature_bytes: [u8; 64] = signature
                    .bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| SignatureError::InvalidSignatureMaterial)?;
                let dalek_signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
                verifying_key
                    .verify_strict(message, &dalek_signature)
                    .map_err(|_| SignatureError::VerificationFailed)
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey {
    algorithm: KeyAlgorithm,
    bytes: [u8; 32],
}

impl SecretKey {
    pub fn from_bytes(algorithm: KeyAlgorithm, bytes: [u8; 32]) -> Self {
        Self { algorithm, bytes }
    }

    pub fn from_hex(algorithm: KeyAlgorithm, value: &str) -> Result<Self, KeyMaterialError> {
        Ok(Self {
            algorithm,
            bytes: decode_hex_32(value)?,
        })
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn write_hex(&self, output: &mut String) {
        encode_hex_into(&self.bytes, output);
    }

    pub fn to_hex(&self) -> String {
        encode_hex(&self.bytes)
    }

    pub fn public_key(&self) -> PublicKey {
        match self.algorithm {
            KeyAlgorithm::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.bytes);
                PublicKey::from_bytes(
                    KeyAlgorithm::Ed25519,
                    signing_key.verifying_key().to_bytes(),
                )
            }
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature, SignatureError> {
        match self.algorithm {
            KeyAlgorithm::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.bytes);
                let signature = ed25519_dalek::Signer::sign(&signing_key, message);
                Ok(Signature {
                    algorithm: KeyAlgorithm::Ed25519,
                    bytes: signature.to_bytes().to_vec(),
                })
            }
        }
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    algorithm: KeyAlgorithm,
    bytes: Vec<u8>,
}

impl Signature {
    pub fn from_bytes(algorithm: KeyAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvelope {
    payload: Vec<u8>,
    signer: PublicKey,
    signature: Signature,
}

impl SignedEnvelope {
    pub fn signed(
        secret_key: &SecretKey,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self, SignatureError> {
        let payload = payload.into();
        let signer = secret_key.public_key();
        let signature = secret_key.sign(&payload)?;
        Ok(Self {
            payload,
            signer,
            signature,
        })
    }

    pub fn from_parts(payload: Vec<u8>, signer: PublicKey, signature: Signature) -> Self {
        Self {
            payload,
            signer,
            signature,
        }
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn signer(&self) -> &PublicKey {
        &self.signer
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        self.signer.verify(&self.payload, &self.signature)
    }

    pub fn verify_signed_by(&self, expected_signer: &PublicKey) -> Result<(), SignatureError> {
        if &self.signer != expected_signer {
            return Err(SignatureError::ExpectedSignerMismatch);
        }

        self.verify()
    }
}

#[derive(Debug, Error)]
pub enum KeyMaterialError {
    #[error("unsupported key algorithm `{0}`")]
    UnsupportedAlgorithm(String),
    #[error("expected exactly 64 hex characters for 32-byte key material")]
    InvalidHexLength,
    #[error("invalid hex at byte index {index}")]
    InvalidHexByte { index: usize },
}

#[derive(Debug, Error)]
pub enum KeyGenerationError {
    #[error("key generation failed: {0}")]
    Failed(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignatureError {
    #[error("signature and key algorithm mismatch (`{key:?}` vs `{signature:?}`)")]
    AlgorithmMismatch {
        key: KeyAlgorithm,
        signature: KeyAlgorithm,
    },
    #[error("invalid signature material for verification")]
    InvalidSignatureMaterial,
    #[error("invalid key material for signing or verification")]
    InvalidKeyMaterial,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("embedded signer does not match expected signer")]
    ExpectedSignerMismatch,
}

fn decode_hex_32(input: &str) -> Result<[u8; 32], KeyMaterialError> {
    let trimmed = input.trim();
    if trimmed.len() != 64 {
        return Err(KeyMaterialError::InvalidHexLength);
    }

    let mut bytes = [0u8; 32];
    for (index, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let chunk =
            std::str::from_utf8(chunk).map_err(|_| KeyMaterialError::InvalidHexByte { index })?;
        bytes[index] = u8::from_str_radix(chunk, 16)
            .map_err(|_| KeyMaterialError::InvalidHexByte { index })?;
    }
    Ok(bytes)
}

fn encode_hex(input: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    encode_hex_into(input, &mut out);
    out
}

fn encode_hex_into(input: &[u8; 32], output: &mut String) {
    for byte in input {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
}
