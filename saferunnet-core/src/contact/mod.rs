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

    /// Build a RouterContact from an Oxen chain ServiceNodeEntry.
    /// The pubkey is decoded from the hex-encoded ed25519 key.
    /// Addresses are left empty — they must be populated via DHT intro-set lookup
    /// once the router has joined the network.
    pub fn from_service_node_entry(ed25519_hex: &str, funded: bool, active: bool) -> Option<Self> {
        let pubkey_bytes = hex::decode(ed25519_hex).ok()?;
        if pubkey_bytes.len() != 32 {
            return None;
        }
        // Only accept funded + active nodes
        if !funded || !active {
            return None;
        }
        let mut rc = Self::new(pubkey_bytes);
        rc.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Some(rc)
    }

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



/// Router identifier (32-byte public key hash).
/// Lokinet C++ equivalent: llarp/ RouterID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouterId(pub [u8; 32]);

impl RouterId {
    pub fn from_contact(rc: &RouterContact) -> Self {
        let mut id = [0u8; 32];
        let len = rc.pubkey.len().min(32);
        id[..len].copy_from_slice(&rc.pubkey[..len]);
        RouterId(id)
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self { RouterId(bytes) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

impl std::fmt::Display for RouterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0.iter().take(8) { write!(f, "{:02x}", byte)?; }
        Ok(())
    }
}

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;

/// 32-byte hash-derived key for DHT introset lookups.
/// Lokinet C++ equivalent: llarp/contact/tag.hpp Tag
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Tag(pub [u8; 32]);

impl Tag {
    /// Derive a tag from a human-readable name using SHA-256.
    pub fn from_name(name: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        let digest = hasher.finalize();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&digest);
        Tag(tag)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// True if the first `bits` bits of this tag match the given prefix.
    pub fn matches_prefix(&self, prefix: &[u8], bits: usize) -> bool {
        if bits == 0 {
            return true;
        }
        let bytes = bits / 8;
        for i in 0..bytes {
            if i >= prefix.len() || self.0[i] != prefix[i] {
                return false;
            }
        }
        let remaining = bits % 8;
        if remaining > 0 && bytes < prefix.len() && bytes < 32 {
            let mask = 0xFFu8.wrapping_shl(8 - remaining as u32);
            (self.0[bytes] & mask) == (prefix[bytes] & mask)
        } else {
            true
        }
    }
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0.iter().take(8) {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Encrypted client contact stored in DHT introset.
/// Lokinet C++ equivalent: llarp/contact/ EncryptedClientContact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedClientContact {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Tag,
    pub expires_at: u64,
}

impl EncryptedClientContact {
    pub fn new(ciphertext: Vec<u8>, nonce: Vec<u8>, tag: Tag, expires_at: u64) -> Self {
        Self {
            ciphertext,
            nonce,
            tag,
            expires_at,
        }
    }

    /// Check if this contact has expired at the given timestamp.
    pub fn is_expired_at(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// Thread-safe contact database with TTL-based expiration.
/// Lokinet C++ equivalent: llarp/nodedb.hpp NodeDB (contact store portion)
#[derive(Debug)]
pub struct ContactDB {
    entries: RwLock<HashMap<RouterId, (RouterContact, u64)>>,
    /// Default TTL in seconds for stored contacts
    default_ttl: u64,
}

impl ContactDB {
    /// Create a new empty ContactDB with the given default TTL (seconds).
    pub fn new(default_ttl: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            default_ttl,
        }
    }

    /// Store or update a RouterContact. Returns true if it was a new entry.
    pub fn put(&self, rc: RouterContact) -> bool {
        let rid = RouterId::from_contact(&rc);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut entries = self.entries.write();
        let is_new = !entries.contains_key(&rid);
        entries.insert(rid, (rc, now));
        is_new
    }

    /// Get a RouterContact by RouterId, if not expired.
    pub fn get(&self, rid: &RouterId) -> Option<RouterContact> {
        let entries = self.entries.read();
        let (rc, inserted_at) = entries.get(rid)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now - *inserted_at >= self.default_ttl {
            return None;
        }
        Some(rc.clone())
    }

    /// Remove a RouterContact by RouterId. Returns the removed contact if it existed.
    pub fn remove(&self, rid: &RouterId) -> Option<RouterContact> {
        self.entries.write().remove(rid).map(|(rc, _)| rc)
    }

    /// Number of contacts currently stored (including expired).
    pub fn count(&self) -> usize {
        self.entries.read().len()
    }

    /// Return all non-expired RouterContacts.
    pub fn all_rcs(&self) -> Vec<RouterContact> {
        let entries = self.entries.read();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        entries
            .values()
            .filter(|(_, inserted_at)| now - *inserted_at < self.default_ttl)
            .map(|(rc, _)| rc.clone())
            .collect()
    }

    /// Remove expired entries. Returns the number of entries removed.
    pub fn expire(&self) -> usize {
        let mut entries = self.entries.write();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let before = entries.len();
        entries.retain(|_, (_, inserted_at)| now - *inserted_at < self.default_ttl);
        before - entries.len()
    }

    /// Visit all non-expired contacts with a closure.
    pub fn visit_all<F: FnMut(&RouterContact)>(&self, mut f: F) {
        let entries = self.entries.read();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for (rc, inserted_at) in entries.values() {
            if now - *inserted_at < self.default_ttl {
                f(rc);
            }
        }
    }

    /// Get a random subset of up to `count` non-expired RouterContacts.
    pub fn get_random_rcs(&self, count: usize) -> Vec<RouterContact> {
        use rand::seq::SliceRandom;
        let mut rcs = self.all_rcs();
        let mut rng = rand::thread_rng();
        rcs.shuffle(&mut rng);
        rcs.truncate(count);
        rcs
    }

    /// Check if we have a contact for the given RouterId that is not expired.
    pub fn has(&self, rid: &RouterId) -> bool {
        let entries = self.entries.read();
        match entries.get(rid) {
            None => false,
            Some((_, inserted_at)) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                now - *inserted_at < self.default_ttl
            }
        }
    }
}

impl Default for ContactDB {
    fn default() -> Self {
        Self::new(3600) // 1 hour default TTL
    }
}

#[cfg(test)]
mod tests_contactdb {
    use super::*;

    fn make_rc(pubkey: u8) -> RouterContact {
        let mut key = vec![0u8; 32];
        key[0] = pubkey;
        RouterContact::new(key)
    }

    #[test]
    fn test_tag_from_name_consistent() {
        let tag1 = Tag::from_name("alice");
        let tag2 = Tag::from_name("alice");
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_tag_from_name_different() {
        let tag1 = Tag::from_name("alice");
        let tag2 = Tag::from_name("bob");
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_tag_matches_prefix() {
        let tag = Tag::from_name("test");
        // A 0-bit prefix always matches.
        assert!(tag.matches_prefix(&[], 0));
        // The prefix of the tag itself should match.
        assert!(tag.matches_prefix(&tag.0, 256));
    }

    #[test]
    fn test_encrypted_client_contact_expiry() {
        let tag = Tag::from_name("client1");
        let ecc = EncryptedClientContact::new(
            vec![1, 2, 3],
            vec![4, 5, 6],
            tag,
            1000,
        );
        assert!(!ecc.is_expired_at(500));
        assert!(ecc.is_expired_at(1000));
        assert!(ecc.is_expired_at(2000));
    }

    #[test]
    fn test_contact_db_put_get() {
        let db = ContactDB::new(3600);
        let rc = make_rc(1);
        let rid = RouterId::from_contact(&rc);
        assert!(db.put(rc.clone()));
        let retrieved = db.get(&rid);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().pubkey, rc.pubkey);
    }

    #[test]
    fn test_contact_db_put_existing() {
        let db = ContactDB::new(3600);
        let rc = make_rc(1);
        assert!(db.put(rc.clone())); // first put: new
        assert!(!db.put(rc.clone())); // second put: update
        assert_eq!(db.count(), 1);
    }

    #[test]
    fn test_contact_db_remove() {
        let db = ContactDB::new(3600);
        let rc = make_rc(1);
        let rid = RouterId::from_contact(&rc);
        db.put(rc.clone());
        assert_eq!(db.count(), 1);
        let removed = db.remove(&rid);
        assert!(removed.is_some());
        assert_eq!(db.count(), 0);
        assert!(db.get(&rid).is_none());
    }

    #[test]
    fn test_contact_db_all_rcs() {
        let db = ContactDB::new(3600);
        db.put(make_rc(1));
        db.put(make_rc(2));
        db.put(make_rc(3));
        let all = db.all_rcs();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_contact_db_expire() {
        let db = ContactDB::new(0); // TTL = 0 means immediately expired
        db.put(make_rc(1));
        db.put(make_rc(2));
        // All entries are immediately expired because TTL=0.
        let removed = db.expire();
        assert_eq!(removed, 2);
        assert_eq!(db.count(), 0);
        assert!(db.all_rcs().is_empty());
    }

    #[test]
    fn test_contact_db_has() {
        let db = ContactDB::new(3600);
        let rc = make_rc(1);
        let rid = RouterId::from_contact(&rc);
        assert!(!db.has(&rid));
        db.put(rc);
        assert!(db.has(&rid));
    }

    #[test]
    fn test_contact_db_visit_all() {
        let db = ContactDB::new(3600);
        db.put(make_rc(1));
        db.put(make_rc(2));
        let mut count = 0;
        db.visit_all(|_| count += 1);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_contact_db_default() {
        let db = ContactDB::default();
        assert_eq!(db.count(), 0);
        assert_eq!(db.default_ttl, 3600);
    }

    #[test]
    fn test_contact_db_get_random_rcs() {
        let db = ContactDB::new(3600);
        for i in 0..10 {
            db.put(make_rc(i));
        }
        let random = db.get_random_rcs(5);
        assert_eq!(random.len(), 5);
    }
}

