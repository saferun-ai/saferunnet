use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Reachability testing for service nodes.
/// Lokinet C++ equivalent: llarp/consensus/reachability_testing.hpp reachability_testing
pub struct ReachabilityTester {
    /// Nodes currently in "failed" status with (key, next_test_time, failure_count)
    failing: Vec<(Vec<u8>, Instant, u32)>,
    failing_set: HashSet<Vec<u8>>,
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
            failing_set: HashSet::new(),
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

    #[test]
    fn test_add_and_remove_failing() {
        let mut rt = ReachabilityTester::new();
        let key = b"node1".to_vec();
        rt.add_failing_node(key.clone(), 0);
        assert_eq!(rt.get_failing(Instant::now()).len(), 0); // Not due yet
        rt.remove_node_from_failing(&key);
        // Should be empty now
    }
}
