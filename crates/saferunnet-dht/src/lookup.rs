use saferunnet_crypto::PublicKey;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LookupError {
    #[error("lookup exhausted without finding target")]
    Exhausted,
    #[error("no peers available to query")]
    NoPeers,
}

#[derive(Debug, Clone)]
pub struct LookupResult {
    pub closest: Vec<PublicKey>,
    pub queries: usize,
}

pub struct IterativeLookup {
    target: PublicKey,
    queried: Vec<PublicKey>,
    candidates: Vec<PublicKey>,
    alpha: usize,
    max_queries: usize,
}

impl IterativeLookup {
    pub fn new(target: PublicKey, bootstrap: Vec<PublicKey>) -> Self {
        Self {
            target,
            queried: Vec::new(),
            candidates: bootstrap,
            alpha: 3,
            max_queries: 20,
        }
    }

    pub fn with_alpha(mut self, alpha: usize) -> Self {
        self.alpha = alpha;
        self
    }

    pub fn with_max_queries(mut self, max: usize) -> Self {
        self.max_queries = max;
        self
    }

    pub fn next_round(&mut self) -> Option<Vec<PublicKey>> {
        if self.queried.len() >= self.max_queries || self.candidates.is_empty() {
            return None;
        }

        let remaining = self.max_queries.saturating_sub(self.queried.len());
        let count = self.alpha.min(self.candidates.len()).min(remaining);
        if count == 0 {
            return None;
        }
        let next: Vec<PublicKey> = self.candidates.drain(..count).collect();

        self.queried.extend(next.iter().cloned());
        Some(next)
    }

    pub fn add_results(&mut self, peers: Vec<PublicKey>) {
        for peer in peers {
            if self.queried.iter().any(|q| q.to_bytes() == peer.to_bytes()) {
                continue;
            }
            if self
                .candidates
                .iter()
                .any(|c| c.to_bytes() == peer.to_bytes())
            {
                continue;
            }
            self.candidates.push(peer);
        }

        self.candidates.sort_by(|a, b| {
            let da = crate::routing::RoutingTable::xor_distance(a, &self.target);
            let db = crate::routing::RoutingTable::xor_distance(b, &self.target);
            da.cmp(&db)
        });
    }

    pub fn is_exhausted(&self) -> bool {
        self.candidates.is_empty() || self.queried.len() >= self.max_queries
    }

    pub fn closest_peers(&self, count: usize) -> Vec<PublicKey> {
        let mut all = self.queried.clone();
        all.sort_by(|a, b| {
            let da = crate::routing::RoutingTable::xor_distance(a, &self.target);
            let db = crate::routing::RoutingTable::xor_distance(b, &self.target);
            da.cmp(&db)
        });
        all.into_iter().take(count).collect()
    }

    pub fn queries_count(&self) -> usize {
        self.queried.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saferunnet_crypto::KeyAlgorithm;

    fn make_key(seed: u8) -> PublicKey {
        let bytes = [seed; 32];
        PublicKey::from_bytes(KeyAlgorithm::Ed25519, bytes)
    }

    #[test]
    fn iterative_lookup_seeds_from_bootstrap() {
        let target = make_key(0xFF);
        let bootstrap = vec![make_key(0x01), make_key(0x02), make_key(0x03)];

        let mut lookup = IterativeLookup::new(target, bootstrap);

        let round = lookup.next_round().unwrap();
        assert_eq!(round.len(), 3);
        assert_eq!(lookup.queries_count(), 3);
    }

    #[test]
    fn iterative_lookup_adds_results() {
        let target = make_key(0xFF);
        let bootstrap = vec![make_key(0x01)];

        let mut lookup = IterativeLookup::new(target, bootstrap);
        let _ = lookup.next_round().unwrap();

        lookup.add_results(vec![make_key(0xFE), make_key(0xFD)]);

        let round = lookup.next_round().unwrap();
        assert_eq!(round.len(), 2);
    }

    #[test]
    fn iterative_lookup_deduplicates() {
        let target = make_key(0xFF);
        let bootstrap = vec![make_key(0x01)];

        let mut lookup = IterativeLookup::new(target, bootstrap);
        let _ = lookup.next_round().unwrap();

        lookup.add_results(vec![make_key(0x01)]);

        assert!(lookup.is_exhausted());
    }

    #[test]
    fn iterative_lookup_exhausted_after_max_queries() {
        let target = make_key(0xFF);
        let bootstrap: Vec<PublicKey> = (0..25).map(make_key).collect();

        let mut lookup = IterativeLookup::new(target, bootstrap).with_max_queries(10);

        let mut total = 0;
        while let Some(round) = lookup.next_round() {
            total += round.len();
        }

        assert!(total <= 10);
        assert!(lookup.is_exhausted());
    }
}
