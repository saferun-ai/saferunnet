use thiserror::Error;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    algorithm: KeyAlgorithm,
    bytes: [u8; 32],
}

impl PublicKey {
    pub fn from_hex(algorithm: KeyAlgorithm, value: &str) -> Result<Self, KeyMaterialError> {
        Ok(Self {
            algorithm,
            bytes: decode_hex_32(value)?,
        })
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    pub fn to_hex(&self) -> String {
        encode_hex(&self.bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey {
    algorithm: KeyAlgorithm,
    bytes: [u8; 32],
}

impl SecretKey {
    pub fn from_hex(algorithm: KeyAlgorithm, value: &str) -> Result<Self, KeyMaterialError> {
        Ok(Self {
            algorithm,
            bytes: decode_hex_32(value)?,
        })
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    pub fn to_hex(&self) -> String {
        encode_hex(&self.bytes)
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
    for byte in input {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
