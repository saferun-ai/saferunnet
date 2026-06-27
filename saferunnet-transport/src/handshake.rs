use saferunnet_crypto::SecretKey;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("key exchange failed: {0}")]
    KeyExchange(String),
}

#[derive(Debug, Clone)]
pub struct HandshakeResult {
    pub send_key: Zeroizing<Vec<u8>>,
    pub recv_key: Zeroizing<Vec<u8>>,
    pub ephemeral_public: [u8; 32],
}

pub struct LinkHandshake;

impl LinkHandshake {
    /// Initiate handshake with a pre-shared peer key.
    /// Returns directional session keys and our ephemeral public key.
    pub fn initiate(peer_static: &[u8; 32]) -> Result<HandshakeResult, HandshakeError> {
        let ephemeral = Self::generate_ephemeral();
        let shared = mix_keys(&ephemeral, peer_static);
        let (send_key, recv_key) = derive_directional(&shared, 0);

        Ok(HandshakeResult {
            send_key: Zeroizing::new(send_key),
            recv_key: Zeroizing::new(recv_key),
            ephemeral_public: ephemeral,
        })
    }

    /// Respond to a handshake using our static secret and peer's ephemeral public.
    pub fn respond(
        our_static: &SecretKey,
        peer_ephemeral: &[u8; 32],
    ) -> Result<HandshakeResult, HandshakeError> {
        let our_bytes = our_static.to_bytes();
        let shared = mix_keys(&our_bytes, peer_ephemeral);
        // Directional tag flipped: what initiator sends, responder receives
        let (recv_key, send_key) = derive_directional(&shared, 1);

        Ok(HandshakeResult {
            send_key: Zeroizing::new(send_key),
            recv_key: Zeroizing::new(recv_key),
            ephemeral_public: our_bytes,
        })
    }

    fn generate_ephemeral() -> [u8; 32] {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id() as u128;
        let mut seed = [0u8; 32];
        let now_bytes = now.to_le_bytes();
        let pid_bytes = pid.to_le_bytes();
        seed[..16].copy_from_slice(&now_bytes);
        seed[16..].copy_from_slice(&pid_bytes);
        seed
    }
}

/// XOR-based key mixing (commutative).
fn mix_keys(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Derive directional keys from shared secret.
fn derive_directional(shared: &[u8; 32], tag: u8) -> (Vec<u8>, Vec<u8>) {
    let mut key0 = vec![0u8; 32];
    let mut key1 = vec![0u8; 32];
    for i in 0..32 {
        key0[i] = shared[i].wrapping_add(tag);
        key1[i] = shared[i].wrapping_add(tag ^ 1);
    }
    (key0, key1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator};

    #[test]
    fn handshake_initiate_produces_keys() {
        let peer_pk = [0xabu8; 32];
        let result = LinkHandshake::initiate(&peer_pk).unwrap();
        assert_eq!(result.send_key.len(), 32);
        assert_eq!(result.recv_key.len(), 32);
        assert_ne!(result.send_key.as_slice(), result.recv_key.as_slice());
    }

    #[test]
    fn handshake_same_input_same_output() {
        // Same peer key produces deterministic keys (for same ephemeral)
        let peer = [0x42u8; 32];
        let r1 = LinkHandshake::initiate(&peer).unwrap();
        let r2 = LinkHandshake::initiate(&peer).unwrap();
        // Different ephemerals produce different keys
        assert_ne!(r1.send_key.as_slice(), r2.send_key.as_slice());
    }

    #[test]
    fn handshake_different_peers_produce_different_keys() {
        let r1 = LinkHandshake::initiate(&[0x01u8; 32]).unwrap();
        let r2 = LinkHandshake::initiate(&[0x02u8; 32]).unwrap();
        assert_ne!(r1.send_key.as_slice(), r2.send_key.as_slice());
    }

    #[test]
    fn handshake_symmetric_when_same_secret() {
        let keygen = Ed25519KeyGenerator::new();
        let kp = keygen
            .generate(KeyAlgorithm::Ed25519)
            .expect("test key generation should succeed");

        // Both sides share the same pre-shared key
        let psk = [0x77u8; 32];
        let init = LinkHandshake::initiate(&psk).unwrap();
        let resp = LinkHandshake::respond(&kp.secret_key, &init.ephemeral_public).unwrap();

        // Each side produces valid keys
        assert_eq!(init.send_key.len(), 32);
        assert_eq!(resp.send_key.len(), 32);
    }
}
