use saferunnet_crypto::PublicKey;
use saferunnet_path::{PathDescriptor, PathState};
use thiserror::Error;

use crate::onion::{ONION_LAYER_SIZE, OnionError, OnionRouter};

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
    /// Create a new path builder.
    pub fn new() -> Self {
        Self {
            onion: OnionRouter::new(),
            min_hops: 2,
            max_hops: 5,
            next_path_id: 1,
        }
    }

    /// Set the minimum number of hops per path.
    pub fn with_min_hops(mut self, min: usize) -> Self {
        self.min_hops = min;
        self
    }

    /// Set the maximum number of hops per path.
    pub fn with_max_hops(mut self, max: usize) -> Self {
        self.max_hops = max;
        self
    }

    /// Select a path from available nodes.
    ///
    /// Picks up to `max_hops` nodes from the pool, ensuring at least `min_hops`.
    /// Nodes are selected deterministically from the shuffled pool.
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

    /// Build an onion-wrapped payload for transmission through a path.
    pub fn build_onion_payload(
        &self,
        path: &PathDescriptor,
        session_nonce: &[u8; ONION_LAYER_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, OnionError> {
        self.onion.wrap(&path.hops, session_nonce, plaintext)
    }

    /// Unwrap one layer at a given hop position.
    pub fn unwrap_hop(
        &self,
        hop_public_key: &PublicKey,
        session_nonce: &[u8; ONION_LAYER_SIZE],
        hop_index: usize,
        payload: &[u8],
    ) -> Result<Vec<u8>, OnionError> {
        self.onion
            .unwrap(hop_public_key, session_nonce, hop_index, payload)
    }

    /// Returns the onion router for direct use.
    pub fn onion(&self) -> &OnionRouter {
        &self.onion
    }

    /// Returns the current next path ID.
    pub fn next_path_id(&self) -> u64 {
        self.next_path_id
    }
}

impl Default for PathBuilder {
    fn default() -> Self {
        Self::new()
    }
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

    fn make_key(seed: u8) -> PublicKey {
        PublicKey::from_bytes(KeyAlgorithm::Ed25519, [seed; 32])
    }

    fn make_nonce(seed: u8) -> [u8; 32] {
        let mut n = [0u8; 32];
        n[0] = seed;
        n
    }

    #[test]
    fn select_path_picks_nodes() {
        let mut builder = PathBuilder::new().with_min_hops(2).with_max_hops(3);
        let nodes: Vec<_> = (0..10).map(make_key).collect();

        let path = builder.select_path(&nodes).unwrap();
        assert_eq!(path.hops.len(), 3);
        assert_eq!(path.path_id, 1);
        assert_eq!(path.state, PathState::Building);
    }

    #[test]
    fn select_path_respects_min_hops() {
        let mut builder = PathBuilder::new().with_min_hops(2).with_max_hops(10);
        let nodes: Vec<_> = (0..4).map(make_key).collect();

        let path = builder.select_path(&nodes).unwrap();
        assert!(path.hops.len() >= 2);
    }

    #[test]
    fn select_path_rejects_insufficient_nodes() {
        let mut builder = PathBuilder::new().with_min_hops(5);
        let nodes: Vec<_> = (0..3).map(make_key).collect();

        let result = builder.select_path(&nodes);
        assert!(matches!(
            result,
            Err(PathBuildError::InsufficientNodes { .. })
        ));
    }

    #[test]
    fn path_ids_increment() {
        let mut builder = PathBuilder::new().with_min_hops(1);
        let nodes: Vec<_> = (0..2).map(make_key).collect();

        let p1 = builder.select_path(&nodes).unwrap();
        let p2 = builder.select_path(&nodes).unwrap();
        let p3 = builder.select_path(&nodes).unwrap();

        assert_eq!(p1.path_id, 1);
        assert_eq!(p2.path_id, 2);
        assert_eq!(p3.path_id, 3);
    }

    #[test]
    fn build_and_unwrap_onion_through_path() {
        let builder = PathBuilder::new();
        let nodes: Vec<_> = (0..3).map(make_key).collect();
        let path = PathDescriptor {
            path_id: 1,
            hops: nodes.clone(),
            state: PathState::Established,
        };
        let nonce = make_nonce(42);
        let plaintext = b"path onion test data";

        let wrapped = builder
            .build_onion_payload(&path, &nonce, plaintext)
            .unwrap();

        let mut payload = wrapped;
        for (i, hop) in path.hops.iter().enumerate() {
            payload = builder.unwrap_hop(hop, &nonce, i, &payload).unwrap();
        }
        assert_eq!(payload, plaintext);
    }

    #[test]
    fn default_min_hops_is_2() {
        let mut builder = PathBuilder::new();
        let nodes: Vec<_> = (0..1).map(make_key).collect();
        let result = builder.select_path(&nodes);
        assert!(result.is_err());
    }
}
