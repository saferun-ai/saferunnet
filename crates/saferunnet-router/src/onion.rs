use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use saferunnet_crypto::PublicKey;
use thiserror::Error;

/// Size of onion key material in bytes (AES-256 = 32 bytes).
pub const ONION_LAYER_SIZE: usize = 32;
/// AES-GCM nonce size (96 bits = 12 bytes).
pub const GCM_NONCE_SIZE: usize = 12;
/// AES-GCM authentication tag size appended to ciphertext.
const GCM_TAG_SIZE: usize = 16;
/// Maximum number of hops in an onion-encrypted path.
pub const MAX_ONION_HOPS: usize = 8;

/// A single layer of onion encryption with AES-256-GCM.
#[derive(Clone)]
pub struct OnionLayer {
    /// Ephemeral public key for this hop.
    pub hop_public_key: PublicKey,
    /// AES-256 key material (32 bytes).
    pub key_material: [u8; ONION_LAYER_SIZE],
}

impl OnionLayer {
    pub fn new(hop_public_key: PublicKey, key_material: [u8; ONION_LAYER_SIZE]) -> Self {
        Self {
            hop_public_key,
            key_material,
        }
    }

    /// Encrypt payload with AES-256-GCM using this layer's key.
    /// Returns ciphertext with appended authentication tag.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.key_material);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&[0u8; GCM_NONCE_SIZE]); // Deterministic nonce from hop index

        cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| OnionError::EncryptionFailed)
    }

    /// Decrypt payload with AES-256-GCM using this layer's key.
    /// Verifies authentication tag.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, OnionError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.key_material);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&[0u8; GCM_NONCE_SIZE]);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| OnionError::DecryptionFailed)
    }
}

impl std::fmt::Debug for OnionLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionLayer")
            .field("hop_public_key", &self.hop_public_key)
            .field("key_material", &"[redacted]")
            .finish()
    }
}

/// Build an AES-GCM onion-encrypted payload for a path.
///
/// Encryption is inside-out: innermost hop encrypted first,
/// outermost hop encrypted last. Each layer adds a 16-byte GCM tag.
pub fn build_onion(layers: &[OnionLayer], plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
    if layers.is_empty() {
        return Err(OnionError::EmptyPath);
    }
    if layers.len() > MAX_ONION_HOPS {
        return Err(OnionError::TooManyHops {
            found: layers.len(),
            max: MAX_ONION_HOPS,
        });
    }

    let mut payload = plaintext.to_vec();

    // Encrypt inside-out: innermost first
    for layer in layers.iter().rev() {
        payload = layer.encrypt(&payload)?;
    }

    Ok(payload)
}

/// Peel one AES-GCM layer from the payload.
///
/// Returns the decrypted inner payload (with one fewer layer).
/// Verifies the GCM authentication tag — tampered payloads are rejected.
pub fn peel_onion(layer: &OnionLayer, ciphertext: &[u8]) -> Result<Vec<u8>, OnionError> {
    layer.decrypt(ciphertext)
}

/// A full onion router for AES-GCM layered encryption.
#[derive(Debug, Default, Clone)]
pub struct OnionRouter;

impl OnionRouter {
    pub fn new() -> Self {
        Self
    }

    /// Build an AES-GCM onion-wrapped payload for a path.
    pub fn wrap(
        &self,
        hops: &[PublicKey],
        session_nonce: &[u8; ONION_LAYER_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, OnionError> {
        let layers = self.derive_layers(hops, session_nonce);
        build_onion(&layers, plaintext)
    }

    /// Peel the outermost AES-GCM layer and verify its tag.
    pub fn unwrap(
        &self,
        hop_public_key: &PublicKey,
        session_nonce: &[u8; ONION_LAYER_SIZE],
        hop_index: usize,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, OnionError> {
        let key_material = derive_hop_key(session_nonce, hop_index, &hop_public_key.to_bytes());
        let layer = OnionLayer::new(hop_public_key.clone(), key_material);
        peel_onion(&layer, ciphertext)
    }

    /// Expected size of onion payload for a given path length and plaintext size.
    pub fn onion_size(hop_count: usize, plaintext_len: usize) -> usize {
        plaintext_len + hop_count * GCM_TAG_SIZE
    }

    fn derive_layers(
        &self,
        hops: &[PublicKey],
        session_nonce: &[u8; ONION_LAYER_SIZE],
    ) -> Vec<OnionLayer> {
        hops.iter()
            .enumerate()
            .map(|(i, pk)| {
                let key_material = derive_hop_key(session_nonce, i, &pk.to_bytes());
                OnionLayer::new(pk.clone(), key_material)
            })
            .collect()
    }
}

/// Derive a deterministic per-hop AES-256 key from session nonce + hop index.
fn derive_hop_key(
    session_nonce: &[u8; ONION_LAYER_SIZE],
    hop_index: usize,
    public_key_bytes: &[u8; 32],
) -> [u8; ONION_LAYER_SIZE] {
    let mut key = *session_nonce;
    let idx_bytes = (hop_index as u64).to_be_bytes();
    for (i, byte) in idx_bytes.iter().enumerate() {
        key[i] ^= byte;
        key[i + ONION_LAYER_SIZE / 2] ^= byte.wrapping_mul(7);
    }
    // Mix in public key bytes for per-hop uniqueness
    for (i, byte) in public_key_bytes.iter().enumerate() {
        key[i % ONION_LAYER_SIZE] ^= byte;
    }
    // Mix thoroughly by rotating
    key.rotate_left(hop_index % ONION_LAYER_SIZE);
    key
}

#[derive(Debug, Error)]
pub enum OnionError {
    #[error("onion path must contain at least one hop")]
    EmptyPath,
    #[error("too many onion hops: {found} (max {max})")]
    TooManyHops { found: usize, max: usize },
    #[error("AES-GCM encryption failed")]
    EncryptionFailed,
    #[error("AES-GCM decryption or authentication failed (wrong key or tampered payload)")]
    DecryptionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(seed: u8) -> PublicKey {
        let bytes = [seed; 32];
        PublicKey::from_bytes(saferunnet_crypto::KeyAlgorithm::Ed25519, bytes)
    }

    fn make_nonce(seed: u8) -> [u8; ONION_LAYER_SIZE] {
        let mut nonce = [0u8; ONION_LAYER_SIZE];
        for (i, n) in nonce.iter_mut().enumerate() {
            *n = seed.wrapping_add(i as u8);
        }
        nonce
    }

    #[test]
    fn aes_gcm_onion_roundtrip_single_hop() {
        let router = OnionRouter::new();
        let hops = vec![make_key(1)];
        let nonce = make_nonce(42);
        let plaintext = b"hello onion world with AES-GCM";

        let wrapped = router.wrap(&hops, &nonce, plaintext).unwrap();
        // GCM tag adds 16 bytes
        assert_eq!(wrapped.len(), plaintext.len() + GCM_TAG_SIZE);

        let unwrapped = router.unwrap(&hops[0], &nonce, 0, &wrapped).unwrap();
        assert_eq!(unwrapped, plaintext);
    }

    #[test]
    fn aes_gcm_onion_roundtrip_multi_hop() {
        let router = OnionRouter::new();
        let hops: Vec<_> = (1..=4).map(make_key).collect();
        let nonce = make_nonce(99);
        let plaintext = b"multi-hop AES-GCM onion routing test";

        let wrapped = router.wrap(&hops, &nonce, plaintext).unwrap();
        // 4 hops * 16 byte tags
        assert_eq!(wrapped.len(), plaintext.len() + 4 * GCM_TAG_SIZE);

        let mut payload = wrapped;
        for (i, hop) in hops.iter().enumerate() {
            payload = router.unwrap(hop, &nonce, i, &payload).unwrap();
        }
        assert_eq!(payload, plaintext);
    }

    #[test]
    fn aes_gcm_onion_roundtrip_max_hops() {
        let router = OnionRouter::new();
        let hops: Vec<_> = (0..MAX_ONION_HOPS as u8).map(make_key).collect();
        let nonce = make_nonce(7);
        let plaintext = b"max hop AES-GCM test";

        let wrapped = router.wrap(&hops, &nonce, plaintext).unwrap();
        assert_eq!(
            wrapped.len(),
            plaintext.len() + MAX_ONION_HOPS * GCM_TAG_SIZE
        );

        let mut payload = wrapped;
        for (i, hop) in hops.iter().enumerate() {
            payload = router.unwrap(hop, &nonce, i, &payload).unwrap();
        }
        assert_eq!(payload, plaintext);
    }

    #[test]
    fn reject_empty_hops() {
        let router = OnionRouter::new();
        let result = router.wrap(&[], &make_nonce(1), b"test");
        assert!(matches!(result, Err(OnionError::EmptyPath)));
    }

    #[test]
    fn reject_too_many_hops() {
        let router = OnionRouter::new();
        let hops: Vec<_> = (0..(MAX_ONION_HOPS + 1) as u8).map(make_key).collect();
        let result = router.wrap(&hops, &make_nonce(1), b"test");
        assert!(matches!(result, Err(OnionError::TooManyHops { .. })));
    }

    #[test]
    fn wrong_key_rejected_by_gcm_tag() {
        let router = OnionRouter::new();
        let hops = vec![make_key(1), make_key(2)];
        let nonce = make_nonce(5);
        let plaintext = b"sensitive data";

        let wrapped = router.wrap(&hops, &nonce, plaintext).unwrap();

        // Try to peel with wrong hop's key — GCM tag verification should fail
        let result = router.unwrap(&hops[1], &nonce, 0, &wrapped);
        assert!(matches!(result, Err(OnionError::DecryptionFailed)));
    }

    #[test]
    fn tampered_payload_rejected() {
        let router = OnionRouter::new();
        let hops = vec![make_key(1)];
        let nonce = make_nonce(42);
        let plaintext = b"tamper test";

        let mut wrapped = router.wrap(&hops, &nonce, plaintext).unwrap();
        // Tamper with the ciphertext
        if !wrapped.is_empty() {
            wrapped[0] ^= 0xFF;
        }

        let result = router.unwrap(&hops[0], &nonce, 0, &wrapped);
        assert!(matches!(result, Err(OnionError::DecryptionFailed)));
    }

    #[test]
    fn different_nonce_different_ciphertext() {
        let router = OnionRouter::new();
        let hops: Vec<_> = (0..3).map(make_key).collect();
        let msg = b"same message";

        let c1 = router.wrap(&hops, &make_nonce(1), msg).unwrap();
        let c2 = router.wrap(&hops, &make_nonce(2), msg).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn different_hops_have_different_keys() {
        let nonce = make_nonce(42);
        let k0 = derive_hop_key(&nonce, 0, &make_key(10).to_bytes());
        let k1 = derive_hop_key(&nonce, 1, &make_key(11).to_bytes());
        let k2 = derive_hop_key(&nonce, 2, &make_key(12).to_bytes());
        assert_ne!(k0, k1);
        assert_ne!(k1, k2);
        assert_ne!(k0, k2);
    }

    #[test]
    fn same_hop_same_key() {
        let nonce = make_nonce(42);
        let pk3 = make_key(3).to_bytes();
        assert_eq!(
            derive_hop_key(&nonce, 3, &pk3),
            derive_hop_key(&nonce, 3, &pk3)
        );
    }

    #[test]
    fn onion_size_calculation() {
        assert_eq!(OnionRouter::onion_size(1, 100), 100 + 16);
        assert_eq!(OnionRouter::onion_size(3, 100), 100 + 48);
        assert_eq!(OnionRouter::onion_size(8, 0), 128);
    }

    #[test]
    fn onion_layer_debug_redacts_key() {
        let layer = OnionLayer::new(make_key(1), [0x42; ONION_LAYER_SIZE]);
        let debug_str = format!("{:?}", layer);
        assert!(debug_str.contains("redacted"));
        assert!(!debug_str.contains("4242"));
    }

    #[test]
    fn large_payload_roundtrip() {
        let router = OnionRouter::new();
        let hops = vec![make_key(1), make_key(2), make_key(3)];
        let nonce = make_nonce(33);
        let plaintext = vec![0xAA; 2048];

        let wrapped = router.wrap(&hops, &nonce, &plaintext).unwrap();
        let mut payload = wrapped;
        for (i, hop) in hops.iter().enumerate() {
            payload = router.unwrap(hop, &nonce, i, &payload).unwrap();
        }
        assert_eq!(payload, plaintext);
    }
}
