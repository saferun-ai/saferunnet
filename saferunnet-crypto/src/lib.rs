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

pub struct SignedEnvelopeCodec;

impl SignedEnvelopeCodec {
    const VERSION: u8 = 1;
    const HEADER_LEN: usize = 11;

    pub fn encode(envelope: &SignedEnvelope) -> Result<Vec<u8>, EnvelopeCodecError> {
        let signer_bytes = envelope.signer().to_bytes();
        let signature_bytes = envelope.signature().to_bytes();
        let payload = envelope.payload();
        let signer_len =
            u16::try_from(signer_bytes.len()).map_err(|_| EnvelopeCodecError::LengthOverflow {
                field: "signer",
                length: signer_bytes.len(),
                max: u16::MAX as usize,
            })?;
        let signature_len = u16::try_from(signature_bytes.len()).map_err(|_| {
            EnvelopeCodecError::LengthOverflow {
                field: "signature",
                length: signature_bytes.len(),
                max: u16::MAX as usize,
            }
        })?;
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| EnvelopeCodecError::LengthOverflow {
                field: "payload",
                length: payload.len(),
                max: u32::MAX as usize,
            })?;
        let mut encoded = Vec::with_capacity(
            Self::HEADER_LEN + signer_bytes.len() + signature_bytes.len() + payload.len(),
        );

        encoded.push(Self::VERSION);
        encoded.push(encode_algorithm(envelope.signer().algorithm()));
        encoded.push(encode_algorithm(envelope.signature().algorithm()));
        encoded.extend_from_slice(&signer_len.to_be_bytes());
        encoded.extend_from_slice(&signature_len.to_be_bytes());
        encoded.extend_from_slice(&payload_len.to_be_bytes());
        encoded.extend_from_slice(&signer_bytes);
        encoded.extend_from_slice(&signature_bytes);
        encoded.extend_from_slice(payload);
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<SignedEnvelope, EnvelopeCodecError> {
        if input.len() < Self::HEADER_LEN {
            return Err(EnvelopeCodecError::Truncated);
        }

        let mut cursor = input;
        let version = take_exact(&mut cursor, 1)?[0];
        if version != Self::VERSION {
            return Err(EnvelopeCodecError::UnsupportedVersion(version));
        }

        let signer_algorithm = decode_algorithm(take_exact(&mut cursor, 1)?[0])?;
        let signature_algorithm = decode_algorithm(take_exact(&mut cursor, 1)?[0])?;

        let signer_len = u16::from_be_bytes(
            take_exact(&mut cursor, 2)?
                .try_into()
                .expect("take_exact guarantees exact byte count"),
        ) as usize;
        let signature_len = u16::from_be_bytes(
            take_exact(&mut cursor, 2)?
                .try_into()
                .expect("take_exact guarantees exact byte count"),
        ) as usize;
        let payload_len = u32::from_be_bytes(
            take_exact(&mut cursor, 4)?
                .try_into()
                .expect("take_exact guarantees exact byte count"),
        ) as usize;

        if signer_len != 32 {
            return Err(EnvelopeCodecError::InvalidSignerLength(signer_len));
        }
        if signature_len != expected_signature_length(signature_algorithm) {
            return Err(EnvelopeCodecError::InvalidSignatureLength {
                algorithm: signature_algorithm.as_str(),
                length: signature_len,
            });
        }

        let signer_bytes: [u8; 32] = take_exact(&mut cursor, signer_len)?
            .try_into()
            .expect("validated signer length must be 32 bytes");
        let signature = Signature::from_bytes(
            signature_algorithm,
            take_exact(&mut cursor, signature_len)?.to_vec(),
        );
        let payload = take_exact(&mut cursor, payload_len)?.to_vec();

        if !cursor.is_empty() {
            return Err(EnvelopeCodecError::Malformed);
        }

        Ok(SignedEnvelope::from_parts(
            payload,
            PublicKey::from_bytes(signer_algorithm, signer_bytes),
            signature,
        ))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeCodecError {
    #[error("unsupported signed envelope codec version `{0}`")]
    UnsupportedVersion(u8),
    #[error("unsupported key algorithm id `{0}` in signed envelope codec")]
    UnsupportedAlgorithm(u8),
    #[error("invalid signer length `{0}` in signed envelope codec")]
    InvalidSignerLength(usize),
    #[error(
        "invalid signature length `{length}` for algorithm `{algorithm}` in signed envelope codec"
    )]
    InvalidSignatureLength {
        algorithm: &'static str,
        length: usize,
    },
    #[error("length overflow for `{field}` in signed envelope codec: `{length}` exceeds `{max}`")]
    LengthOverflow {
        field: &'static str,
        length: usize,
        max: usize,
    },
    #[error("truncated signed envelope bytes")]
    Truncated,
    #[error("malformed signed envelope bytes")]
    Malformed,
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

fn encode_algorithm(algorithm: KeyAlgorithm) -> u8 {
    match algorithm {
        KeyAlgorithm::Ed25519 => 1,
    }
}

fn decode_algorithm(encoded: u8) -> Result<KeyAlgorithm, EnvelopeCodecError> {
    match encoded {
        1 => Ok(KeyAlgorithm::Ed25519),
        _ => Err(EnvelopeCodecError::UnsupportedAlgorithm(encoded)),
    }
}

fn expected_signature_length(algorithm: KeyAlgorithm) -> usize {
    match algorithm {
        KeyAlgorithm::Ed25519 => 64,
    }
}

fn take_exact<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], EnvelopeCodecError> {
    if input.len() < count {
        return Err(EnvelopeCodecError::Truncated);
    }

    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}
