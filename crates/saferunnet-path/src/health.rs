use crate::{PathDescriptor, PathState};

pub trait PathHealthChecker {
    fn check(&mut self, path: &PathDescriptor) -> PathState;
}

pub struct PingHealthChecker;

impl PingHealthChecker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PingHealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl PathHealthChecker for PingHealthChecker {
    fn check(&mut self, path: &PathDescriptor) -> PathState {
        match path.state {
            PathState::Building => PathState::Building,
            PathState::Established => PathState::Established,
            PathState::Failing => PathState::Dead,
            PathState::Dead => PathState::Dead,
        }
    }
}
