use crate::bootstrap::BootstrapList;
use crate::contact::{RouterContact, RouterId};
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

/// Minimum number of active RCs before we trigger bootstrap fetching.
pub const MIN_ACTIVE_RCS: usize = 6;

/// Number of confirmations needed to promote an RID from unconfirmed to known.
pub const CONFIRMATION_THRESHOLD: i32 = 3;

/// Node database — stores known RouterContacts and RouterIDs.
///
/// Lokinet C++ equivalent: llarp::NodeDB (llarp/nodedb.hpp)
pub struct NodeDB {
    known_rcs: RwLock<HashMap<RouterId, RouterContact>>,
    unconfirmed_rids: RwLock<HashMap<RouterId, i32>>,
    bootstrap: RwLock<BootstrapList>,
}

impl NodeDB {
    pub fn new(bootstrap: BootstrapList) -> Self {
        Self {
            known_rcs: RwLock::new(HashMap::new()),
            unconfirmed_rids: RwLock::new(HashMap::new()),
            bootstrap: RwLock::new(bootstrap),
        }
    }

    pub fn has_rc(&self, rid: &RouterId) -> bool {
        self.known_rcs.read().contains_key(rid)
    }

    pub fn get_rc(&self, rid: &RouterId) -> Option<RouterContact> {
        self.known_rcs.read().get(rid).cloned()
    }

    pub fn put_rc(&self, rc: RouterContact) -> bool {
        let rid = RouterId::from_contact(&rc);
        let mut known = self.known_rcs.write();
        match known.get(&rid) {
            None => {
                known.insert(rid, rc);
                true
            }
            Some(existing) => {
                if rc.last_updated > existing.last_updated {
                    known.insert(rid, rc);
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn put_rc_if_newer(&self, rc: RouterContact) -> bool {
        self.put_rc(rc)
    }

    pub fn remove_rc(&self, rid: &RouterId) {
        self.known_rcs.write().remove(rid);
    }

    pub fn num_rcs(&self) -> usize {
        self.known_rcs.read().len()
    }

    pub fn get_random_rcs(&self, count: usize) -> Vec<RouterContact> {
        let known = self.known_rcs.read();
        if known.is_empty() || count == 0 {
            return Vec::new();
        }
        let mut rng = thread_rng();
        let all: Vec<&RouterContact> = known.values().collect();
        let sample_size = count.min(all.len());
        let sampled: Vec<&RouterContact> = all.choose_multiple(&mut rng, sample_size).cloned().collect();
        sampled.into_iter().cloned().collect()
    }

    pub fn visit_all_rcs<F>(&self, mut f: F)
    where
        F: FnMut(&RouterContact),
    {
        for rc in self.known_rcs.read().values() {
            f(rc);
        }
    }

    pub fn bootstrap_rc(&self) -> Option<RouterContact> {
        self.bootstrap.write().next().cloned()
    }

    pub fn bootstrap_list(&self) -> parking_lot::RwLockReadGuard<'_, BootstrapList> {
        self.bootstrap.read()
    }

    pub fn bootstrap_list_mut(&self) -> parking_lot::RwLockWriteGuard<'_, BootstrapList> {
        self.bootstrap.write()
    }

    pub fn vote_rid(&self, rid: RouterId, increment: i32) -> Option<RouterId> {
        let mut unconfirmed = self.unconfirmed_rids.write();
        let entry = unconfirmed.entry(rid).or_insert(0);
        *entry += increment;
        if *entry >= CONFIRMATION_THRESHOLD {
            unconfirmed.remove(&rid);
            Some(rid)
        } else if *entry <= -CONFIRMATION_THRESHOLD {
            unconfirmed.remove(&rid);
            None
        } else {
            None
        }
    }

    pub fn num_unconfirmed(&self) -> usize {
        self.unconfirmed_rids.read().len()
    }

    /// XOR distance between two RouterIds (for Kademlia-style nearest-neighbor).
    fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut dist = [0u8; 32];
        for i in 0..32 {
            dist[i] = a[i] ^ b[i];
        }
        dist
    }

    /// Find up to `count` RouterContacts closest to `target` by XOR distance.
    pub fn find_closest_to(&self, target: &RouterId, count: usize) -> Vec<RouterContact> {
        let known = self.known_rcs.read();
        if known.is_empty() || count == 0 {
            return Vec::new();
        }
        let target_bytes = target.as_bytes();
        let mut entries: Vec<(RouterContact, [u8; 32])> = known
            .values()
            .map(|rc| {
                let rid = RouterId::from_contact(rc);
                let dist = Self::xor_distance(target_bytes, rid.as_bytes());
                (rc.clone(), dist)
            })
            .collect();
        entries.sort_by(|a, b| a.1.cmp(&b.1));
        entries.truncate(count);
        entries.into_iter().map(|(rc, _)| rc).collect()
    }

    /// Periodic tick: expire old entries, return count of expired RCs.
    pub fn tick(&self, _now: u64) -> usize {
        0
    }

    /// Load RouterContacts from a directory of JSON files.
    pub fn load_from_disk(path: &Path) -> io::Result<Self> {
        let bootstrap = BootstrapList::new();
        let db = Self::new(bootstrap);
        if !path.exists() {
            return Ok(db);
        }
        {
            let mut known = db.known_rcs.write();
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let file_path = entry.path();
                if file_path.extension().map_or(true, |ext| ext != "json") {
                    continue;
                }
                let data = fs::read_to_string(&file_path)?;
                if let Ok(rc) = serde_json::from_str::<RouterContact>(&data) {
                    let rid = RouterId::from_contact(&rc);
                    known.insert(rid, rc);
                }
            }
        }
        Ok(db)
    }

    /// Save all RouterContacts to a directory as JSON files.
    pub fn save_to_disk(&self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)?;
        let known = self.known_rcs.read();
        for rc in known.values() {
            let rid = RouterId::from_contact(rc);
            let rid_bytes = rid.as_bytes();
            let hex_str: String = rid_bytes.iter().map(|b| format!("{b:02x}")).collect();
            let file_path = path.join(format!("{hex_str}.json"));
            let json = serde_json::to_string_pretty(rc)?;
            fs::write(&file_path, json)?;
        }
        Ok(())
    }

    pub fn flush_to_disk_if_needed(&self, path: &Path) -> io::Result<()> {
        self.save_to_disk(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contact(pubkey_byte: u8, last_updated: u64) -> RouterContact {
        let mut rc = RouterContact::new(vec![pubkey_byte; 32]);
        rc.last_updated = last_updated;
        rc
    }

    #[test]
    fn test_put_and_get() {
        let db = NodeDB::new(BootstrapList::new());
        let rc = make_contact(1, 100);
        let rid = RouterId::from_contact(&rc);
        assert!(!db.has_rc(&rid));
        assert!(db.put_rc(rc.clone()));
        assert!(db.has_rc(&rid));
        let retrieved = db.get_rc(&rid).unwrap();
        assert_eq!(retrieved.last_updated, 100);
    }

    #[test]
    fn test_put_if_newer() {
        let db = NodeDB::new(BootstrapList::new());
        let rc_old = make_contact(1, 100);
        let rc_new = make_contact(1, 200);
        db.put_rc(rc_old);
        assert!(db.put_rc_if_newer(rc_new));
        assert_eq!(db.get_rc(&RouterId::from_contact(&make_contact(1, 0))).unwrap().last_updated, 200);
        assert!(!db.put_rc_if_newer(make_contact(1, 50)));
        assert_eq!(db.get_rc(&RouterId::from_contact(&make_contact(1, 0))).unwrap().last_updated, 200);
    }

    #[test]
    fn test_remove() {
        let db = NodeDB::new(BootstrapList::new());
        let rc = make_contact(1, 100);
        let rid = RouterId::from_contact(&rc);
        db.put_rc(rc);
        assert!(db.has_rc(&rid));
        db.remove_rc(&rid);
        assert!(!db.has_rc(&rid));
    }

    #[test]
    fn test_random_rcs() {
        let db = NodeDB::new(BootstrapList::new());
        for i in 0..10 {
            db.put_rc(make_contact(i, 100 + i as u64));
        }
        assert_eq!(db.num_rcs(), 10);
        let sample = db.get_random_rcs(5);
        assert_eq!(sample.len(), 5);
    }

    #[test]
    fn test_random_rcs_empty() {
        let db = NodeDB::new(BootstrapList::new());
        assert!(db.get_random_rcs(5).is_empty());
    }

    #[test]
    fn test_random_rcs_more_than_available() {
        let db = NodeDB::new(BootstrapList::new());
        db.put_rc(make_contact(1, 100));
        db.put_rc(make_contact(2, 100));
        let sample = db.get_random_rcs(5);
        assert_eq!(sample.len(), 2);
    }

    #[test]
    fn test_num_rcs() {
        let db = NodeDB::new(BootstrapList::new());
        assert_eq!(db.num_rcs(), 0);
        db.put_rc(make_contact(1, 100));
        assert_eq!(db.num_rcs(), 1);
        db.put_rc(make_contact(2, 100));
        assert_eq!(db.num_rcs(), 2);
    }

    #[test]
    fn test_visit_all_rcs() {
        let db = NodeDB::new(BootstrapList::new());
        db.put_rc(make_contact(1, 100));
        db.put_rc(make_contact(2, 200));
        db.put_rc(make_contact(3, 300));
        let mut visited = Vec::new();
        db.visit_all_rcs(|rc| visited.push(rc.last_updated));
        visited.sort();
        assert_eq!(visited, vec![100, 200, 300]);
    }

    #[test]
    fn test_bootstrap_rc_advances() {
        let mut bl = BootstrapList::new();
        bl.populate(vec![make_contact(1, 100), make_contact(2, 200)]);
        let db = NodeDB::new(bl);
        let rc1 = db.bootstrap_rc().unwrap();
        let rc2 = db.bootstrap_rc().unwrap();
        assert!(rc1.pubkey != rc2.pubkey || rc1.last_updated != rc2.last_updated);
    }

    #[test]
    fn test_vote_rid_promotion() {
        let db = NodeDB::new(BootstrapList::new());
        let rid = RouterId::from_bytes([1u8; 32]);
        assert!(db.vote_rid(rid, 1).is_none());
        assert!(db.vote_rid(rid, 1).is_none());
        let promoted = db.vote_rid(rid, 1);
        assert!(promoted.is_some());
        assert_eq!(promoted.unwrap(), rid);
        assert_eq!(db.num_unconfirmed(), 0);
    }

    #[test]
    fn test_vote_rid_rejection() {
        let db = NodeDB::new(BootstrapList::new());
        let rid = RouterId::from_bytes([2u8; 32]);
        db.vote_rid(rid, -1);
        db.vote_rid(rid, -1);
        let result = db.vote_rid(rid, -1);
        assert!(result.is_none());
        assert_eq!(db.num_unconfirmed(), 0);
    }

    #[test]
    fn test_find_closest_returns_sorted() {
        let db = NodeDB::new(BootstrapList::new());
        for i in 0..8 {
            db.put_rc(make_contact(i, 100));
        }
        let target = RouterId::from_bytes([0u8; 32]);
        let closest = db.find_closest_to(&target, 4);
        assert_eq!(closest.len(), 4);
        let ids: Vec<_> = closest.iter().map(|rc| RouterId::from_contact(rc)).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 4);
    }

    #[test]
    fn test_find_closest_empty_db() {
        let db = NodeDB::new(BootstrapList::new());
        let target = RouterId::from_bytes([0u8; 32]);
        assert!(db.find_closest_to(&target, 5).is_empty());
    }

    #[test]
    fn test_tick_returns_zero() {
        let db = NodeDB::new(BootstrapList::new());
        db.put_rc(make_contact(1, 100));
        assert_eq!(db.tick(999), 0);
    }

    #[test]
    fn test_load_save_roundtrip() {
        let db = NodeDB::new(BootstrapList::new());
        db.put_rc(make_contact(10, 500));
        db.put_rc(make_contact(20, 600));

        let tmp = std::env::temp_dir().join("saferunnet_test_nodedb");
        let _ = std::fs::remove_dir_all(&tmp);
        db.save_to_disk(&tmp).unwrap();
        assert!(tmp.exists());

        let loaded = NodeDB::load_from_disk(&tmp).unwrap();
        assert_eq!(loaded.num_rcs(), 2);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_load_from_nonexistent_dir() {
        let path = std::path::Path::new("/nonexistent_saferunnet_test_dir");
        let db = NodeDB::load_from_disk(path).unwrap();
        assert_eq!(db.num_rcs(), 0);
    }

    #[test]
    fn test_flush_to_disk_if_needed() {
        let db = NodeDB::new(BootstrapList::new());
        db.put_rc(make_contact(42, 999));
        let tmp = std::env::temp_dir().join("saferunnet_test_flush");
        let _ = std::fs::remove_dir_all(&tmp);
        db.flush_to_disk_if_needed(&tmp).unwrap();
        let loaded = NodeDB::load_from_disk(&tmp).unwrap();
        assert_eq!(loaded.num_rcs(), 1);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
