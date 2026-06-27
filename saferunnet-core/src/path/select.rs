use crate::path::{PathDescriptor, PathState};
use saferunnet_crypto::PublicKey;

pub trait PathSelector {
    fn select_path(&self, target: &PublicKey) -> Option<&PathDescriptor>;
}

pub struct FirstAvailableSelector {
    paths: Vec<PathDescriptor>,
}

impl FirstAvailableSelector {
    pub fn new() -> Self {
        Self { paths: Vec::new() }
    }

    pub fn insert(&mut self, path: PathDescriptor) {
        self.paths.push(path);
    }

    pub fn remove(&mut self, path_id: u64) {
        self.paths.retain(|p| p.path_id != path_id);
    }

    pub fn all_paths(&self) -> &[PathDescriptor] {
        &self.paths
    }
}

impl Default for FirstAvailableSelector {
    fn default() -> Self {
        Self::new()
    }
}

impl PathSelector for FirstAvailableSelector {
    fn select_path(&self, target: &PublicKey) -> Option<&PathDescriptor> {
        self.paths
            .iter()
            .find(|p| p.state == PathState::Established && p.hops.last() == Some(target))
    }
}
