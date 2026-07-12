use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// A hash set where entries automatically expire after a TTL.
/// Entries are lazily cleaned up on insertion and explicitly via `expire()`.
/// Lokinet C++ equivalent: llarp/util/decaying_hashset.hpp
pub struct DecayingHashSet<K: Hash + Eq + Clone> {
    entries: HashMap<K, Instant>,
    ttl: Duration,
}

impl<K: Hash + Eq + Clone> DecayingHashSet<K> {
    /// Create a new set with the given entry TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
        }
    }

    /// Insert a key. Returns true if it was newly inserted (or re-inserted after expiry).
    pub fn insert(&mut self, key: K) -> bool {
        self.expire();
        let now = Instant::now();
        if self.entries.contains_key(&key) {
            // Update timestamp
            self.entries.insert(key, now);
            false
        } else {
            self.entries.insert(key, now);
            true
        }
    }

    /// Check if the key exists and hasn't expired.
    pub fn contains(&self, key: &K) -> bool {
        match self.entries.get(key) {
            Some(inserted) => inserted.elapsed() < self.ttl,
            None => false,
        }
    }

    /// Remove a key.
    pub fn remove(&mut self, key: &K) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Remove all expired entries. Returns count of removed entries.
    pub fn expire(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, inserted| inserted.elapsed() < self.ttl);
        before - self.entries.len()
    }

    /// Number of entries (including expired ones, until cleaned).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_contains() {
        let mut set = DecayingHashSet::new(Duration::from_secs(60));
        assert!(set.insert(1));
        assert!(set.contains(&1));
        assert!(!set.contains(&2));
    }

    #[test]
    fn test_insert_duplicate_returns_false() {
        let mut set = DecayingHashSet::new(Duration::from_secs(60));
        assert!(set.insert(1));
        assert!(!set.insert(1));
    }

    #[test]
    fn test_remove() {
        let mut set = DecayingHashSet::new(Duration::from_secs(60));
        set.insert(1);
        assert!(set.remove(&1));
        assert!(!set.contains(&1));
        assert!(!set.remove(&1));
    }

    #[test]
    fn test_expire_removes_old_entries() {
        let mut set = DecayingHashSet::new(Duration::from_millis(1));
        set.insert(1);
        std::thread::sleep(Duration::from_millis(10));
        assert!(!set.contains(&1));
        let removed = set.expire();
        assert!(removed >= 1);
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_clear() {
        let mut set = DecayingHashSet::new(Duration::from_secs(60));
        set.insert(1);
        set.insert(2);
        set.clear();
        assert!(set.is_empty());
    }
}
