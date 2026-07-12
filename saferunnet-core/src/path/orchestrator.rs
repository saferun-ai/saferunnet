use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::nodedb::NodeDB;
use crate::path::{PathDescriptor, PathState};
use crate::router::path_build::PathBuilder;
use saferunnet_crypto::PublicKey;

pub const MAX_PATHS: usize = 32;
pub const DEFAULT_DESIRED_PATHS: usize = 4;
pub const MIN_PATH_BUILD_INTERVAL: Duration = Duration::from_secs(5);
pub const PATH_ROTATION_INTERVAL: Duration = Duration::from_secs(1200);
pub const PATH_BUILD_TIMEOUT: Duration = Duration::from_secs(10);
pub const PATH_EXPIRY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Default)]
pub struct BuildStats {
    pub attempts: u64,
    pub successes: u64,
    pub build_fails: u64,
    pub path_fails: u64,
    pub timeouts: u64,
}

pub struct PathOrchestrator {
    node_db: Arc<NodeDB>,
    path_builder: PathBuilder,
    paths: HashMap<u64, PathEntry>,
    desired_paths: usize,
    last_build: Option<Instant>,
    build_interval: Duration,
    stats: BuildStats,
    next_rotation: Option<Instant>,
}

struct PathEntry {
    descriptor: PathDescriptor,
    created_at: Instant,
    build_deadline: Option<Instant>,
}

impl PathOrchestrator {
    pub fn new(node_db: Arc<NodeDB>) -> Self {
        Self {
            node_db,
            path_builder: PathBuilder::new(),
            paths: HashMap::new(),
            desired_paths: DEFAULT_DESIRED_PATHS,
            last_build: None,
            build_interval: MIN_PATH_BUILD_INTERVAL,
            stats: BuildStats::default(),
            next_rotation: Some(Instant::now() + PATH_ROTATION_INTERVAL),
        }
    }

    pub fn with_desired_paths(mut self, count: usize) -> Self {
        self.desired_paths = count.min(MAX_PATHS);
        self
    }

    pub fn with_hops(mut self, min: usize, max: usize) -> Self {
        self.path_builder = self.path_builder.with_min_hops(min).with_max_hops(max);
        self
    }

    pub fn tick(&mut self, now: Instant) {
        self.expire_paths(now);
        self.maybe_rotate(now);
        self.maybe_build(now);
    }

    pub fn num_active_paths(&self) -> usize {
        self.paths.values().filter(|e| e.descriptor.state == PathState::Established).count()
    }

    pub fn num_paths(&self) -> usize { self.paths.len() }

    pub fn stats(&self) -> &BuildStats { &self.stats }

    pub fn on_build_response(&mut self, path_id: u64, success: bool) {
        if let Some(entry) = self.paths.get_mut(&path_id) {
            if success {
                entry.descriptor.state = PathState::Established;
                entry.build_deadline = None;
                self.stats.successes += 1;
            } else {
                entry.descriptor.state = PathState::Failing;
                self.stats.build_fails += 1;
            }
        }
    }

    pub fn on_path_died(&mut self, path_id: u64) {
        if let Some(entry) = self.paths.get_mut(&path_id) {
            entry.descriptor.state = PathState::Dead;
            self.stats.path_fails += 1;
        }
    }

    pub fn get_random_path(&self) -> Option<&PathDescriptor> {
        use rand::seq::IteratorRandom;
        let mut rng = rand::thread_rng();
        self.paths.values()
            .filter(|e| e.descriptor.state == PathState::Established)
            .choose(&mut rng)
            .map(|e| &e.descriptor)
    }

    // ── private ──

    fn maybe_build(&mut self, now: Instant) {
        let total = self.paths.values()
            .filter(|e| e.descriptor.state == PathState::Established || e.descriptor.state == PathState::Building)
            .count();
        if total >= self.desired_paths { return; }
        if let Some(last) = self.last_build {
            if now.duration_since(last) < self.build_interval { return; }
        }
        for _ in 0..(self.desired_paths - total) {
            self.build_one(now);
        }
    }

    fn build_one(&mut self, now: Instant) {
        self.stats.attempts += 1;
        self.last_build = Some(now);
        let rcs = self.node_db.get_random_rcs(10);
        let min = self.path_builder.min_hops();
        if rcs.len() < min { self.stats.build_fails += 1; return; }
        let keys: Vec<PublicKey> = rcs.iter().map(|rc| {
            let mut arr = [0u8; 32]; let len = rc.pubkey.len().min(32);
            arr[..len].copy_from_slice(&rc.pubkey[..len]);
            PublicKey::from_bytes(saferunnet_crypto::KeyAlgorithm::Ed25519, arr)
        }).collect();
        match self.path_builder.select_path(&keys) {
            Ok(d) => { self.paths.insert(d.path_id, PathEntry { descriptor: d, created_at: now, build_deadline: Some(now + PATH_BUILD_TIMEOUT) }); }
            Err(_) => { self.stats.build_fails += 1; }
        }
    }

    fn expire_paths(&mut self, now: Instant) {
        let mut dead = Vec::new();
        for (id, e) in &self.paths {
            if let Some(dl) = e.build_deadline { if now >= dl { self.stats.timeouts += 1; dead.push(*id); continue; } }
            if e.descriptor.state == PathState::Dead && now.duration_since(e.created_at) > PATH_EXPIRY { dead.push(*id); }
        }
        for id in dead { self.paths.remove(&id); }
    }

    fn maybe_rotate(&mut self, now: Instant) {
        if let Some(rot) = self.next_rotation {
            if now >= rot {
                let oldest = self.paths.iter()
                    .filter(|(_, e)| e.descriptor.state == PathState::Established)
                    .min_by_key(|(_, e)| e.created_at).map(|(id, _)| *id);
                if let Some(id) = oldest {
                    if let Some(e) = self.paths.get_mut(&id) { e.descriptor.state = PathState::Failing; }
                }
                self.next_rotation = Some(now + PATH_ROTATION_INTERVAL);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::BootstrapList;

    fn make_db() -> Arc<NodeDB> { Arc::new(NodeDB::new(BootstrapList::new())) }

    fn make_entry(state: PathState, deadline: Option<Instant>) -> PathEntry {
        PathEntry { descriptor: PathDescriptor { path_id: 1, hops: vec![], state }, created_at: Instant::now(), build_deadline: deadline }
    }

    #[test] fn test_create() { let o = PathOrchestrator::new(make_db()); assert_eq!(o.num_paths(), 0); }
    #[test] fn test_config() { let o = PathOrchestrator::new(make_db()).with_desired_paths(6); assert_eq!(o.desired_paths, 6); }
    #[test] fn test_tick_empty() { let mut o = PathOrchestrator::new(make_db()); o.tick(Instant::now()); assert_eq!(o.num_paths(), 0); }

    #[test] fn test_build_success() {
        let mut o = PathOrchestrator::new(make_db());
        o.paths.insert(1, make_entry(PathState::Building, Some(Instant::now() + Duration::from_secs(5))));
        o.on_build_response(1, true);
        assert_eq!(o.paths[&1].descriptor.state, PathState::Established);
        assert_eq!(o.stats.successes, 1);
    }

    #[test] fn test_build_fail() {
        let mut o = PathOrchestrator::new(make_db());
        o.paths.insert(1, make_entry(PathState::Building, None));
        o.on_build_response(1, false);
        assert_eq!(o.paths[&1].descriptor.state, PathState::Failing);
    }

    #[test] fn test_path_died() {
        let mut o = PathOrchestrator::new(make_db());
        o.paths.insert(1, make_entry(PathState::Established, None));
        o.on_path_died(1);
        assert_eq!(o.stats.path_fails, 1);
    }

    #[test] fn test_expire_dead() {
        let mut o = PathOrchestrator::new(make_db());
        o.paths.insert(1, PathEntry { descriptor: PathDescriptor { path_id: 1, hops: vec![], state: PathState::Dead }, created_at: Instant::now() - PATH_EXPIRY - Duration::from_secs(1), build_deadline: None });
        o.tick(Instant::now());
        assert_eq!(o.num_paths(), 0);
    }

    #[test] fn test_build_timeout() {
        let mut o = PathOrchestrator::new(make_db());
        o.paths.insert(1, PathEntry { descriptor: PathDescriptor { path_id: 1, hops: vec![], state: PathState::Building }, created_at: Instant::now() - Duration::from_secs(20), build_deadline: Some(Instant::now() - Duration::from_secs(1)) });
        o.tick(Instant::now());
        assert_eq!(o.num_paths(), 0);
        assert_eq!(o.stats.timeouts, 1);
    }
}
