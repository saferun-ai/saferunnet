use crate::contact::{RouterContact, RouterId};
use rand::seq::SliceRandom;
use rand::thread_rng;

/// Bootstrap node list — maintains a shuffled list of trusted entry-point RouterContacts.
/// 
/// Lokinet C++ equivalent: llarp::BootstrapList (llarp/bootstrap.hpp)
#[derive(Debug)]
pub struct BootstrapList {
    bootstraps: Vec<RouterContact>,
    cursor: usize,
}

impl BootstrapList {
    /// Create an empty bootstrap list.
    pub fn new() -> Self {
        Self {
            bootstraps: Vec::new(),
            cursor: 0,
        }
    }

    /// Populate from a list of contacts (simplified from C++ file-based loading).
    /// In C++ Lokinet, this reads from disk files and embedded fallback blobs.
    /// For the Rust port, we accept pre-parsed RouterContacts directly.
    pub fn populate(&mut self, contacts: Vec<RouterContact>) {
        self.bootstraps = contacts;
        // Remove obsolete entries (stub: C++ uses RelayContact::is_obsolete())
        self.bootstraps.retain(|rc| rc.version > 0);
        self.shuffle();
    }

    /// Return the current bootstrap contact without advancing the cursor.
    pub fn current(&self) -> Option<&RouterContact> {
        if self.bootstraps.is_empty() {
            return None;
        }
        Some(&self.bootstraps[self.cursor % self.bootstraps.len()])
    }

    /// Advance the cursor and return the next bootstrap contact.
    /// Wraps around when the end is reached.
    pub fn next(&mut self) -> Option<&RouterContact> {
        if self.bootstraps.is_empty() {
            return None;
        }
        self.cursor = (self.cursor + 1) % self.bootstraps.len();
        Some(&self.bootstraps[self.cursor])
    }

    /// Advance the cursor; when the end is reached, shuffle the list before wrapping.
    /// C++ equivalent: BootstrapList::next_with_shuffling()
    pub fn next_with_shuffling(&mut self) -> Option<&RouterContact> {
        if self.bootstraps.is_empty() {
            return None;
        }
        self.cursor += 1;
        if self.cursor >= self.bootstraps.len() {
            self.shuffle();
            // shuffle() resets cursor to 0
        }
        Some(&self.bootstraps[self.cursor])
    }

    /// Shuffle the bootstrap list randomly and reset the cursor to the beginning.
    pub fn shuffle(&mut self) {
        let mut rng = thread_rng();
        self.bootstraps.shuffle(&mut rng);
        self.cursor = 0;
    }

    /// Check if a router with the given RouterId is in the bootstrap list.
    pub fn contains(&self, rid: &RouterId) -> bool {
        self.bootstraps
            .iter()
            .any(|rc| RouterId::from_contact(rc) == *rid)
    }

    /// Remove all bootstrap entries.
    pub fn clear(&mut self) {
        self.bootstraps.clear();
        self.cursor = 0;
    }

    /// Number of bootstrap entries.
    pub fn size(&self) -> usize {
        self.bootstraps.len()
    }

    /// Whether the bootstrap list is empty.
    pub fn is_empty(&self) -> bool {
        self.bootstraps.is_empty()
    }
}

impl Default for BootstrapList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contact(pubkey_byte: u8) -> RouterContact {
        let mut rc = RouterContact::new(vec![pubkey_byte; 32]);
        rc.version = 1;
        rc
    }

    #[test]
    fn test_empty() {
        let mut bl = BootstrapList::new();
        assert!(bl.is_empty());
        assert_eq!(bl.size(), 0);
        assert!(bl.current().is_none());
        assert!(bl.next().is_none());
        assert!(bl.next_with_shuffling().is_none());
    }

    #[test]
    fn test_populate_from_contacts() {
        let mut bl = BootstrapList::new();
        let contacts = vec![make_contact(1), make_contact(2), make_contact(3)];
        bl.populate(contacts);
        assert_eq!(bl.size(), 3);
        assert!(!bl.is_empty());
    }

    #[test]
    fn test_current_does_not_advance() {
        let mut bl = BootstrapList::new();
        bl.populate(vec![make_contact(1), make_contact(2)]);
        let first = bl.current().unwrap().pubkey[0];
        let second = bl.current().unwrap().pubkey[0];
        assert_eq!(first, second, "current() should not advance cursor");
    }

    #[test]
    fn test_next_wraps() {
        let mut bl = BootstrapList::new();
        bl.populate(vec![make_contact(1), make_contact(2), make_contact(3)]);
        
        // Advance through all 3
        bl.next(); // cursor now 1
        bl.next(); // cursor now 2
        bl.next(); // cursor now 0 (wrap)
        
        // Should be back at beginning
        assert_eq!(bl.cursor, 0);
    }

    #[test]
    fn test_shuffle_resets_cursor() {
        let mut bl = BootstrapList::new();
        bl.populate(vec![make_contact(1), make_contact(2), make_contact(3)]);
        bl.cursor = 2; // manually advance
        bl.shuffle();
        assert_eq!(bl.cursor, 0);
        assert_eq!(bl.size(), 3);
    }

    #[test]
    fn test_contains() {
        let mut bl = BootstrapList::new();
        let rc = make_contact(42);
        let rid = RouterId::from_contact(&rc);
        bl.populate(vec![make_contact(1), rc.clone(), make_contact(3)]);
        assert!(bl.contains(&rid));
        assert!(!bl.contains(&RouterId::from_contact(&make_contact(99))));
    }

    #[test]
    fn test_clear() {
        let mut bl = BootstrapList::new();
        bl.populate(vec![make_contact(1), make_contact(2)]);
        assert_eq!(bl.size(), 2);
        bl.clear();
        assert!(bl.is_empty());
        assert_eq!(bl.cursor, 0);
    }

    #[test]
    fn test_next_with_shuffling_triggers_shuffle_on_wrap() {
        let mut bl = BootstrapList::new();
        bl.populate(vec![make_contact(1), make_contact(2)]);
        
        // Advance through both
        bl.next_with_shuffling(); // cursor now 1
        bl.next_with_shuffling(); // cursor reaches len=2 => shuffle + reset to 0
        
        assert_eq!(bl.cursor, 0);
        assert_eq!(bl.size(), 2);
    }
}
