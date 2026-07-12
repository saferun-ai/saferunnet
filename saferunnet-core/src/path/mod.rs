pub mod build;
pub mod health;
pub mod path_control;
pub mod select;
pub mod svc_path_build;
pub mod transit_hop;
pub mod orchestrator;

use saferunnet_crypto::PublicKey;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathDescriptor {
    pub path_id: u64,
    pub hops: Vec<PublicKey>,
    pub state: PathState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    Building,
    Established,
    Failing,
    Dead,
}

#[derive(Debug, Error)]
pub enum PathError {
    #[error("path must have at least one hop")]
    EmptyHops,
    #[error("too many hops: {0} (max {1})")]
    TooManyHops(usize, usize),
    #[error("path {0} not found")]
    NotFound(u64),
    #[error("path {0} is in wrong state: {1:?}")]
    WrongState(u64, PathState),
}


impl PathDescriptor {
    pub fn new(path_id: u64, hops: Vec<PublicKey>) -> Self {
        Self { path_id, hops, state: PathState::Building }
    }
    pub fn first_hop(&self) -> Option<&PublicKey> { self.hops.first() }
    pub fn last_hop(&self) -> Option<&PublicKey> { self.hops.last() }
    pub fn len(&self) -> usize { self.hops.len() }
    pub fn is_empty(&self) -> bool { self.hops.is_empty() }

    /// Human-readable path representation with hop chain.
    pub fn to_string(&self) -> String {
        let hops_display: Vec<String> = self.hops
            .iter()
            .map(|pk| {
                let hex_pk = hex::encode(pk.to_bytes());
                let short = &hex_pk[..8.min(hex_pk.len())];
                format!("{}", short)
            })
            .collect();
        format!("Path#{} [{}] ({:?})", self.path_id, hops_display.join(" -> "), self.state)
    }
}

