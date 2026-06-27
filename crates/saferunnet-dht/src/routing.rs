use saferunnet_crypto::PublicKey;
use thiserror::Error;

/// Maximum entries per k-bucket.
pub const K_BUCKET_SIZE: usize = 20;
/// Number of k-buckets (one per bit of the 256-bit key space).
pub const NUM_BUCKETS: usize = 256;

#[derive(Debug, Error)]
pub enum RoutingTableError {
    #[error("bucket is full, cannot evict")]
    BucketFull,
    #[error("entry not found")]
    NotFound,
}

/// A single entry in the routing table.
#[derive(Debug, Clone)]
pub struct RouterEntry {
    pub public_key: PublicKey,
    /// XOR distance from the local node, cached for sorting.
    pub distance: [u8; 32],
    /// Timestamp of last contact (unix seconds).
    pub last_seen: u64,
}

/// Kademlia-style routing table.
///
/// Organizes known peers into k-buckets by XOR distance from the local node.
/// Each bucket holds up to K_BUCKET_SIZE entries, sorted by last-seen time.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    local_key: PublicKey,
    buckets: Vec<Vec<RouterEntry>>,
}

impl RoutingTable {
    /// Create a new routing table for the given local identity.
    pub fn new(local_key: PublicKey) -> Self {
        Self {
            local_key,
            buckets: vec![Vec::new(); NUM_BUCKETS],
        }
    }

    /// Compute the XOR distance between two public keys as a 32-byte array.
    pub fn xor_distance(a: &PublicKey, b: &PublicKey) -> [u8; 32] {
        let a_bytes = a.to_bytes();
        let b_bytes = b.to_bytes();
        let mut dist = [0u8; 32];
        for (i, d) in dist.iter_mut().enumerate() {
            *d = a_bytes[i] ^ b_bytes[i];
        }
        dist
    }

    /// Determine which bucket an entry belongs to, based on XOR distance.
    pub fn bucket_index(distance: &[u8; 32]) -> usize {
        for (i, &byte) in distance.iter().enumerate() {
            if byte != 0 {
                let bit = 7 - byte.leading_zeros() as usize;
                return (31 - i) * 8 + bit;
            }
        }
        0 // Distance zero → our own key
    }

    /// Add or update a peer in the routing table.
    pub fn add(&mut self, entry: RouterEntry) -> Result<(), RoutingTableError> {
        let idx = Self::bucket_index(&entry.distance);

        // Check if already present (update)
        if let Some(existing) = self.buckets[idx]
            .iter_mut()
            .find(|e| e.public_key.to_bytes() == entry.public_key.to_bytes())
        {
            existing.last_seen = entry.last_seen;
            return Ok(());
        }

        // Add if bucket not full
        if self.buckets[idx].len() < K_BUCKET_SIZE {
            self.buckets[idx].push(entry);
            // Sort by last_seen descending (most recent first)
            self.buckets[idx].sort_by_key(|b| std::cmp::Reverse(b.last_seen));
            Ok(())
        } else {
            Err(RoutingTableError::BucketFull)
        }
    }

    /// Find the K closest peers to a target key.
    pub fn find_closest(&self, target: &PublicKey, count: usize) -> Vec<RouterEntry> {
        let mut all: Vec<RouterEntry> = self.buckets.iter().flatten().cloned().collect();

        // Sort by XOR distance to target (ascending)
        all.sort_by(|a, b| {
            let da = Self::xor_distance(&a.public_key, target);
            let db = Self::xor_distance(&b.public_key, target);
            xor_compare(&da, &db)
        });

        all.into_iter().take(count).collect()
    }

    /// Returns the total number of entries across all buckets.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a reference to the local node's public key.
    pub fn local_key(&self) -> &PublicKey {
        &self.local_key
    }
}

/// Compare two XOR distances (both 32-byte arrays).
fn xor_compare(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    for i in 0..32 {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use saferunnet_crypto::KeyAlgorithm;

    fn make_key(seed: u8) -> PublicKey {
        let bytes = [seed; 32];
        PublicKey::from_bytes(KeyAlgorithm::Ed25519, bytes)
    }

    fn make_entry(key: &PublicKey, local: &PublicKey, last_seen: u64) -> RouterEntry {
        RouterEntry {
            public_key: key.clone(),
            distance: RoutingTable::xor_distance(key, local),
            last_seen,
        }
    }

    #[test]
    fn xor_distance_is_symmetric() {
        let a = make_key(0x01);
        let b = make_key(0x02);
        let d1 = RoutingTable::xor_distance(&a, &b);
        let d2 = RoutingTable::xor_distance(&b, &a);
        assert_eq!(d1, d2);
    }

    #[test]
    fn xor_distance_self_is_zero() {
        let a = make_key(0x42);
        let d = RoutingTable::xor_distance(&a, &a);
        assert_eq!(d, [0u8; 32]);
    }

    #[test]
    fn bucket_index_near() {
        // Distance 1 → bucket 0 (closest)
        let mut dist = [0u8; 32];
        dist[31] = 1;
        assert_eq!(RoutingTable::bucket_index(&dist), 0);
    }

    #[test]
    fn bucket_index_far() {
        // Distance with MSB set → bucket 255 (furthest)
        let mut dist = [0u8; 32];
        dist[0] = 0x80;
        assert_eq!(RoutingTable::bucket_index(&dist), 255);
    }

    #[test]
    fn add_and_find_closest() {
        let local = make_key(0x00);
        let mut table = RoutingTable::new(local.clone());

        // Add 5 entries
        for i in 1..=5 {
            let key = make_key(i);
            let entry = make_entry(&key, &local, 1000 + i as u64);
            table.add(entry).unwrap();
        }
        assert_eq!(table.len(), 5);

        let target = make_key(0x02);
        let closest = table.find_closest(&target, 3);
        assert_eq!(closest.len(), 3);
        // First entry should be the target itself or the closest
        assert_eq!(closest[0].public_key.to_bytes(), make_key(0x02).to_bytes());
    }

    #[test]
    fn bucket_filling() {
        let local = make_key(0x00);
        let mut table = RoutingTable::new(local.clone());

        // Add K_BUCKET_SIZE entries to the same bucket (distance pattern)
        for i in 0..K_BUCKET_SIZE {
            let mut bytes = [0u8; 32];
            bytes[30] = 0x01; // first non-zero byte -> same bucket for all entries
            bytes[31] = i as u8; // varies AFTER the bucket-determining byte -> unique entries
            let key = PublicKey::from_bytes(KeyAlgorithm::Ed25519, bytes);
            let dist = RoutingTable::xor_distance(&key, &local);
            let entry = RouterEntry {
                public_key: key,
                distance: dist,
                last_seen: i as u64,
            };
            table.add(entry).unwrap();
        }

        assert_eq!(table.len(), K_BUCKET_SIZE);

        // Try to add one more → bucket full
        let mut bytes = [0u8; 32];
        bytes[30] = 0x01; // same bucket
        bytes[31] = K_BUCKET_SIZE as u8;
        let key = PublicKey::from_bytes(KeyAlgorithm::Ed25519, bytes);
        let dist = RoutingTable::xor_distance(&key, &local);
        let entry = RouterEntry {
            public_key: key,
            distance: dist,
            last_seen: 999,
        };
        assert!(table.add(entry).is_err());
    }
}
