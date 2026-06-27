pub mod build;
pub mod health;
pub mod select;
pub mod path_control;
pub mod svc_path_build;
pub mod transit_hop;

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
