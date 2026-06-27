use crate::path::{PathDescriptor, PathError, PathState};
use saferunnet_crypto::PublicKey;

pub trait PathBuilder {
    fn build_path(
        &mut self,
        target: &PublicKey,
        hop_count: usize,
    ) -> Result<PathDescriptor, PathError>;
}

pub struct RandomPathBuilder {
    next_id: u64,
    router_pool: Vec<PublicKey>,
}

impl RandomPathBuilder {
    pub fn new(router_pool: Vec<PublicKey>) -> Self {
        Self {
            next_id: 1,
            router_pool,
        }
    }
}

impl PathBuilder for RandomPathBuilder {
    fn build_path(
        &mut self,
        target: &PublicKey,
        hop_count: usize,
    ) -> Result<PathDescriptor, PathError> {
        if hop_count == 0 {
            return Err(PathError::EmptyHops);
        }
        if hop_count > self.router_pool.len() {
            return Err(PathError::TooManyHops(hop_count, self.router_pool.len()));
        }

        let path_id = self.next_id;
        self.next_id += 1;

        let mut hops: Vec<PublicKey> = self.router_pool.iter().take(hop_count).cloned().collect();
        hops.push(target.clone());

        Ok(PathDescriptor {
            path_id,
            hops,
            state: PathState::Building,
        })
    }
}
