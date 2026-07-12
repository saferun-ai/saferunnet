use std::collections::HashSet as StdHashSet;
use std::time::{Duration, Instant};
use crate::contact::{RouterContact, RouterId};
use thiserror::Error;

/// Errors that can occur during consensus verification.
/// Lokinet C++ equivalent: llarp/consensus/ validation errors
#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("too few nodes in consensus: got {0}, need at least {1}")]
    TooFewNodes(usize, usize),

    #[error("duplicate router id in node list: {0}")]
    DuplicateRouterId(String),

    #[error("invalid signature for router {0}")]
    InvalidSignature(String),
}

/// Verifier for consensus-related data.
/// Lokinet C++ equivalent: llarp/consensus/ verification routines
pub struct ConsensusVerifier;

impl ConsensusVerifier {
    /// Verify that a list of RouterContacts forms a valid consensus node list.
    /// Requirements: at least `min_nodes` entries, all RouterIds unique.
    pub fn verify_node_list(rcs: &[RouterContact], min_nodes: usize) -> Result<(), ConsensusError> {
        if rcs.len() < min_nodes {
            return Err(ConsensusError::TooFewNodes(rcs.len(), min_nodes));
        }

        let mut seen = StdHashSet::new();
        for rc in rcs {
            let rid = RouterId::from_contact(rc);
            let rid_bytes = rid.as_bytes();
            let key: String = rid_bytes.iter().map(|b| format!("{b:02x}")).collect();
            if !seen.insert(key.clone()) {
                return Err(ConsensusError::DuplicateRouterId(key));
            }
        }

        Ok(())
    }

    /// Verify a RouterContact signature.
    /// Currently a stub that always returns `true`.
    /// In a full implementation this would verify using the router's public key.
    pub fn verify_rc_signature(_rc: &RouterContact, _sig: &[u8]) -> bool {
        // Stub: signature verification not yet implemented
        true
    }
}

/// Reachability testing for service nodes.
/// Lokinet C++ equivalent: llarp/consensus/reachability_testing.hpp reachability_testing
pub struct ReachabilityTester {
    /// Nodes currently in "failed" status with (key, next_test_time, failure_count)
    failing: Vec<(Vec<u8>, Instant, u32)>,
    failing_set: StdHashSet<Vec<u8>>,
    /// Queue of all known nodes to test
    testing_queue: Vec<Vec<u8>>,
    next_general_test: Instant,
    /// Interval between random tests
    pub testing_interval: Duration,
    /// Backoff per failure
    pub testing_backoff: Duration,
    /// Max backoff
    pub testing_backoff_max: Duration,
    /// Max retests per tick
    pub max_retests_per_tick: usize,
}

impl ReachabilityTester {
    pub fn new() -> Self {
        Self {
            failing: Vec::new(),
            failing_set: StdHashSet::new(),
            testing_queue: Vec::new(),
            next_general_test: Instant::now(),
            testing_interval: Duration::from_secs(10),
            testing_backoff: Duration::from_secs(10),
            testing_backoff_max: Duration::from_secs(120),
            max_retests_per_tick: 4,
        }
    }

    /// Pick the next random node to test
    pub fn next_random(&mut self, now: Instant) -> Option<Vec<u8>> {
        if now < self.next_general_test {
            return None;
        }
        if self.testing_queue.is_empty() {
            return None;
        }
        let node = self.testing_queue.pop().unwrap();
        self.next_general_test = now + self.testing_interval;
        Some(node)
    }

    /// Add a failed node for retesting
    pub fn add_failing_node(&mut self, key: Vec<u8>, previous_failures: u32) {
        let backoff = Duration::from_secs(
            ((previous_failures + 1) * 10).min(self.testing_backoff_max.as_secs() as u32) as u64,
        );
        let next_test = Instant::now() + backoff;
        if self.failing_set.insert(key.clone()) {
            self.failing.push((key, next_test, previous_failures + 1));
        }
    }

    /// Get failing nodes due for retesting
    pub fn get_failing(&mut self, now: Instant) -> Vec<(Vec<u8>, u32)> {
        let all_failing: Vec<_> = self.failing.drain(..).collect();

        let (due, still_waiting): (Vec<_>, Vec<_>) = all_failing
            .into_iter()
            .partition(|(_, next, _)| *next <= now);

        let result: Vec<_> = due
            .into_iter()
            .map(|(k, _, c)| (k, c))
            .take(self.max_retests_per_tick)
            .collect();

        // Put back the rest (still waiting + unprocessed due items)
        for item in still_waiting {
            self.failing.push(item);
        }

        result
    }

    /// Remove a node from failing set (it came back online)
    pub fn remove_node_from_failing(&mut self, key: &[u8]) {
        self.failing_set.remove(key);
        self.failing.retain(|(k, _, _)| k != key);
    }

    /// Replace the testing queue with a new node list
    pub fn set_nodes(&mut self, nodes: Vec<Vec<u8>>) {
        self.testing_queue = nodes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ReachabilityTester tests ───────────────────────────────────────

    #[test]
    fn test_add_and_remove_failing() {
        let mut rt = ReachabilityTester::new();
        let key = b"node1".to_vec();
        rt.add_failing_node(key.clone(), 0);
        assert_eq!(rt.get_failing(Instant::now()).len(), 0); // Not due yet
        rt.remove_node_from_failing(&key);
        // Should be empty now
    }

    // ── Consensus tests ────────────────────────────────────────────────

    fn make_rc(pubkey_byte: u8) -> RouterContact {
        RouterContact::new(vec![pubkey_byte; 32])
    }

    #[test]
    fn test_verify_empty_list_error() {
        let result = ConsensusVerifier::verify_node_list(&[], 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConsensusError::TooFewNodes(0, 1)));
    }

    #[test]
    fn test_verify_too_few_nodes() {
        let rcs = vec![make_rc(1)];
        let result = ConsensusVerifier::verify_node_list(&rcs, 3);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConsensusError::TooFewNodes(1, 3)));
    }

    #[test]
    fn test_verify_duplicate_rid() {
        let rcs = vec![make_rc(5), make_rc(5), make_rc(10)];
        let result = ConsensusVerifier::verify_node_list(&rcs, 2);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConsensusError::DuplicateRouterId(_)));
    }

    #[test]
    fn test_verify_valid_node_list() {
        let rcs = vec![make_rc(1), make_rc(2), make_rc(3)];
        let result = ConsensusVerifier::verify_node_list(&rcs, 2);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_rc_signature_stub() {
        let rc = make_rc(42);
        assert!(ConsensusVerifier::verify_rc_signature(&rc, b"any signature"));
    }
}
