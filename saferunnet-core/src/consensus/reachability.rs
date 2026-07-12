use crate::contact::RouterId;
use crate::nodedb::NodeDB;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// Reachability test result for a single router.
#[derive(Debug, Clone)]
pub struct ReachabilityResult {
    pub router_id: RouterId,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub tested_at: Instant,
}

/// Tests reachability of nodes in the NodeDB.
/// Lokinet C++ equivalent: consensus/reachability_testing.cpp
pub struct ReachabilityTester {
    pub(crate) node_db: Arc<NodeDB>,
    pub(crate) results: HashMap<RouterId, ReachabilityResult>,
    pub(crate) last_full_test: Option<Instant>,
}

impl ReachabilityTester {
    pub fn new(node_db: Arc<NodeDB>) -> Self {
        Self {
            node_db,
            results: HashMap::new(),
            last_full_test: None,
        }
    }

    /// Run reachability test on a random set of nodes.
    /// Returns newly tested results.
    pub fn test_sample(&mut self, count: usize) -> Vec<ReachabilityResult> {
        let rcs = self.node_db.get_random_rcs(count);
        let now = Instant::now();
        let mut results = Vec::new();

        for rc in &rcs {
            let rid = RouterId::from_contact(rc);
            // Reachability is determined by whether the node has addresses
            let reachable = !rc.addresses.is_empty();
            let r = ReachabilityResult {
                router_id: rid.clone(),
                reachable,
                latency_ms: None, // Would need actual ping
                tested_at: now,
            };
            self.results.insert(rid, r.clone());
            results.push(r);
        }

        self.last_full_test = Some(now);
        results
    }

    /// Get the last known result for a router.
    pub fn get_result(&self, rid: &RouterId) -> Option<&ReachabilityResult> {
        self.results.get(rid)
    }

    /// Count reachable nodes.
    pub fn reachable_count(&self) -> usize {
        self.results.values().filter(|r| r.reachable).count()
    }

    /// Total tested nodes.
    pub fn tested_count(&self) -> usize {
        self.results.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::BootstrapList;
    use crate::contact::RouterContact;

    fn make_db_with_nodes(count: usize) -> Arc<NodeDB> {
        let db = Arc::new(NodeDB::new(BootstrapList::new()));
        for i in 0..count {
            let mut rc = RouterContact::new(vec![i as u8; 32]);
            rc.addresses.push("10.0.0.1:1090".parse().unwrap());
            rc.version = 1;
            db.put_rc(rc);
        }
        db
    }

    #[test] fn test_empty_db() { let db = Arc::new(NodeDB::new(BootstrapList::new())); let mut t = ReachabilityTester::new(db); let r = t.test_sample(5); assert!(r.is_empty()); }
    #[test] fn test_sample() { let db = make_db_with_nodes(3); let mut t = ReachabilityTester::new(db); let r = t.test_sample(2); assert!(!r.is_empty()); }
    #[test] fn test_reachable_count() { let db = make_db_with_nodes(3); let mut t = ReachabilityTester::new(db); t.test_sample(3); assert_eq!(t.reachable_count(), 3); assert_eq!(t.tested_count(), 3); }
}
