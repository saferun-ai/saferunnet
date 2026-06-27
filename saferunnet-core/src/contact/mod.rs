use saferunnet_crypto::{
    KeyAlgorithm, KeyGenerationError, KeyGenerator, KeyMaterialError, PublicKey, SecretKey,
    Signature, SignatureError,
};
use serde::{Deserialize, Serialize};
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;

/// Router contact information published in introset.
/// Lokinet C++ equivalent: llarp/contact/ RouterContact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterContact {
    /// Router public key (32 bytes)
    pub pubkey: Vec<u8>,
    /// Network address for reachability
    pub addresses: Vec<SocketAddr>,
    /// Protocol version
    pub version: u16,
    /// When this contact was last updated (unix timestamp)
    pub last_updated: u64,
    /// Supported protocols (e.g., quic, exit)
    pub supported_protocols: Vec<String>,
}

impl RouterContact {
    pub fn new(pubkey: Vec<u8>) -> Self {
        Self {
            pubkey,
            addresses: Vec::new(),
            version: 1,
            last_updated: 0,
            supported_protocols: vec!["quic".into()],
        }
    }
}

/// Encrypted SNS record from Oxen chain.
/// Lokinet C++ equivalent: llarp/contact/sns EncryptedSNSRecord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSnsRecord {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Node identity holding key material.
/// Lokinet C++ equivalent: llarp/contact/ RouterID
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl NodeIdentity {
    pub fn new(secret_key: SecretKey) -> Self {
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.secret_key.algorithm()
    }
}

/// Specification for generating a new identity.
#[derive(Debug, Clone)]
pub struct IdentitySpec {
    pub nickname: String,
    pub algorithm: KeyAlgorithm,
}

/// Repository that persists a node identity on the filesystem.
pub struct FileIdentityRepository {
    keyfile: PathBuf,
}

#[derive(Debug, Error)]
pub enum IdentityRepositoryError {
    #[error("key generation failed: {0}")]
    KeyGeneration(#[from] KeyGenerationError),
    #[error("key material error: {0}")]
    KeyMaterial(#[from] KeyMaterialError),
    #[error("I/O error reading or writing key file: {0}")]
    Io(#[from] io::Error),
}

impl FileIdentityRepository {
    pub fn new(keyfile: PathBuf) -> Self {
        Self { keyfile }
    }

    /// Load an existing identity from the key file, or create a new one.
    pub fn load_or_create(
        &self,
        spec: &IdentitySpec,
        generator: &dyn KeyGenerator,
    ) -> Result<NodeIdentity, IdentityRepositoryError> {
        if self.keyfile.exists() {
            let hex = std::fs::read_to_string(&self.keyfile)?;
            let secret_key = SecretKey::from_hex(spec.algorithm, hex.trim())
                .map_err(|e| IdentityRepositoryError::KeyMaterial(e))?;
            Ok(NodeIdentity::new(secret_key))
        } else {
            let keypair = generator.generate(spec.algorithm)?;
            let mut hex = String::new();
            keypair.secret_key.write_hex(&mut hex);
            if let Some(parent) = self.keyfile.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&self.keyfile, hex.as_bytes())?;
            Ok(NodeIdentity::new(keypair.secret_key))
        }
    }
}

/// Cryptographic identity proof signed by a service node.
/// Lokinet C++ equivalent: llarp/auth/ IdentityProof
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProof {
    claim_identity: NodeIdentity,
    signature: Signature,
}

#[derive(Debug, Error)]
pub enum IdentityProofError {
    #[error("identity proof signature verification failed")]
    VerificationFailed,
    #[error("invalid identity proof signature")]
    InvalidSignature(#[from] SignatureError),
    #[error("unsupported algorithm id `{0}`")]
    UnsupportedAlgorithm(u8),
    #[error("truncated identity proof bytes")]
    Truncated,
    #[error("key material error: {0}")]
    KeyMaterial(#[from] KeyMaterialError),
}

impl IdentityProof {
    /// Create a proof by signing with the identity's secret key.
    pub fn sign(identity: &NodeIdentity) -> Result<Self, IdentityProofError> {
        let payload = identity.public_key.to_bytes();
        let signature = identity
            .secret_key
            .sign(&payload)
            .map_err(IdentityProofError::InvalidSignature)?;
        Ok(Self {
            claim_identity: identity.clone(),
            signature,
        })
    }

    /// Encode the proof to bytes.
    pub fn encode(&self) -> Result<Vec<u8>, IdentityProofError> {
        let mut buf = Vec::with_capacity(1 + 32 + 64);
        buf.push(encode_algorithm(self.claim_identity.algorithm()));
        buf.extend_from_slice(&self.claim_identity.public_key.to_bytes());
        let sig_bytes = self.signature.to_bytes();
        buf.extend_from_slice(&sig_bytes);
        Ok(buf)
    }

    /// Decode a proof from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, IdentityProofError> {
        if data.len() < 1 + 32 + 64 {
            return Err(IdentityProofError::Truncated);
        }
        let algorithm = decode_algorithm(data[0])?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&data[1..33]);
        let public_key = PublicKey::from_bytes(algorithm, key_bytes);
        let signature_bytes = data[33..97].to_vec();
        let signature = Signature::from_bytes(algorithm, signature_bytes);
        let secret_key = SecretKey::from_bytes(algorithm, key_bytes); // placeholder, not used for verify
        Ok(Self {
            claim_identity: NodeIdentity {
                secret_key,
                public_key,
            },
            signature,
        })
    }

    /// Verify that this proof is valid.
    pub fn verify(&self) -> Result<(), IdentityProofError> {
        let payload = self.claim_identity.public_key.to_bytes();
        self.claim_identity
            .public_key
            .verify(&payload, &self.signature)
            .map_err(IdentityProofError::InvalidSignature)
    }

    /// Access the claimed identity.
    pub fn claim(&self) -> &NodeIdentity {
        &self.claim_identity
    }
}

fn encode_algorithm(algorithm: KeyAlgorithm) -> u8 {
    match algorithm {
        KeyAlgorithm::Ed25519 => 1,
    }
}

fn decode_algorithm(encoded: u8) -> Result<KeyAlgorithm, IdentityProofError> {
    match encoded {
        1 => Ok(KeyAlgorithm::Ed25519),
        _ => Err(IdentityProofError::UnsupportedAlgorithm(encoded)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_contact_defaults() {
        let rc = RouterContact::new(vec![0u8; 32]);
        assert_eq!(rc.version, 1);
        assert!(rc.supported_protocols.contains(&"quic".to_string()));
    }
}
