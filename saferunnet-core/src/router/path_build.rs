use crate::path::{PathDescriptor, PathState};
use saferunnet_crypto::PublicKey;
use thiserror::Error;

use crate::router::onion::{OnionError, OnionRouter, ONION_LAYER_SIZE};

/// Specification for a single hop in a path being built.
#[derive(Debug, Clone)]
pub struct PathHopSpec {
    pub public_key: PublicKey,
}

/// Builds onion-routed paths from DHT-discovered nodes.
#[derive(Debug, Clone)]
pub struct PathBuilder {
    onion: OnionRouter,
    min_hops: usize,
    max_hops: usize,
    next_path_id: u64,
}

impl PathBuilder {
    pub fn new() -> Self {
        Self {
            onion: OnionRouter::new(),
            min_hops: 2,
            max_hops: 5,
            next_path_id: 1,
        }
    }

    pub fn with_min_hops(mut self, min: usize) -> Self {
        self.min_hops = min;
        self
    }

    pub fn with_max_hops(mut self, max: usize) -> Self {
        self.max_hops = max;
        self
    }

    /// Return the minimum number of hops.
    pub fn min_hops(&self) -> usize {
        self.min_hops
    }

    pub fn select_path(
        &mut self,
        available_nodes: &[PublicKey],
    ) -> Result<PathDescriptor, PathBuildError> {
        if available_nodes.len() < self.min_hops {
            return Err(PathBuildError::InsufficientNodes {
                available: available_nodes.len(),
                required: self.min_hops,
            });
        }

        let hop_count = self.max_hops.min(available_nodes.len()).max(self.min_hops);
        let hops: Vec<PublicKey> = available_nodes[..hop_count].to_vec();
        let path_id = self.next_path_id;
        self.next_path_id = self.next_path_id.wrapping_add(1);

        Ok(PathDescriptor {
            path_id,
            hops,
            state: PathState::Building,
        })
    }

    pub fn build_onion_payload(
        &self,
        path: &PathDescriptor,
        session_nonce: &[u8; ONION_LAYER_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, OnionError> {
        self.onion.wrap(&path.hops, session_nonce, plaintext)
    }

    pub fn unwrap_hop(
        &self,
        hop_public_key: &PublicKey,
        session_nonce: &[u8; ONION_LAYER_SIZE],
        hop_index: usize,
        payload: &[u8],
    ) -> Result<Vec<u8>, OnionError> {
        self.onion.unwrap(hop_public_key, session_nonce, hop_index, payload)
    }

    pub fn onion(&self) -> &OnionRouter { &self.onion }
    pub fn next_path_id(&self) -> u64 { self.next_path_id }
}

impl Default for PathBuilder {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Error)]
pub enum PathBuildError {
    #[error("not enough available nodes: {available} (need at least {required})")]
    InsufficientNodes { available: usize, required: usize },
    #[error("path building error: {0}")]
    Onion(#[from] OnionError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use saferunnet_crypto::KeyAlgorithm;

    fn make_key(seed: u8) -> PublicKey { PublicKey::from_bytes(KeyAlgorithm::Ed25519, [seed; 32]) }
    fn make_nonce(seed: u8) -> [u8; 32] { let mut n = [0u8; 32]; n[0] = seed; n }

    #[test] fn select_path_picks_nodes() { let mut b = PathBuilder::new().with_min_hops(2).with_max_hops(3); let nodes: Vec<_> = (0..10).map(make_key).collect(); let p = b.select_path(&nodes).unwrap(); assert_eq!(p.hops.len(), 3); assert_eq!(p.path_id, 1); }
    #[test] fn select_path_respects_min() { let mut b = PathBuilder::new().with_min_hops(2).with_max_hops(10); let nodes: Vec<_> = (0..4).map(make_key).collect(); assert!(b.select_path(&nodes).unwrap().hops.len() >= 2); }
    #[test] fn select_path_rejects_insufficient() { let mut b = PathBuilder::new().with_min_hops(5); let nodes: Vec<_> = (0..3).map(make_key).collect(); assert!(matches!(b.select_path(&nodes), Err(PathBuildError::InsufficientNodes { .. }))); }
    #[test] fn path_ids_increment() { let mut b = PathBuilder::new().with_min_hops(1); let nodes: Vec<_> = (0..2).map(make_key).collect(); assert_eq!(b.select_path(&nodes).unwrap().path_id, 1); assert_eq!(b.select_path(&nodes).unwrap().path_id, 2); }
    #[test] fn build_and_unwrap_onion() { let b = PathBuilder::new(); let nodes: Vec<_> = (0..3).map(make_key).collect(); let path = PathDescriptor { path_id: 1, hops: nodes.clone(), state: PathState::Established }; let nonce = make_nonce(42); let plaintext = b"onion test data"; let wrapped = b.build_onion_payload(&path, &nonce, plaintext).unwrap(); let mut p = wrapped; for (i, h) in path.hops.iter().enumerate() { p = b.unwrap_hop(h, &nonce, i, &p).unwrap(); } assert_eq!(p, plaintext); }
    #[test] fn default_min_hops() { let mut b = PathBuilder::new(); let nodes: Vec<_> = (0..1).map(make_key).collect(); assert!(b.select_path(&nodes).is_err()); }
}
