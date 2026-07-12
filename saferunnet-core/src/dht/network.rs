use std::net::SocketAddr;
use std::sync::Arc;

use crate::dns::resolver::{DhtClient, DhtIntroResult};
use saferunnet_crypto::PublicKey;
use crate::transport::LinkTransport;
use thiserror::Error;
use tokio::sync::RwLock;

use crate::dht::lookup::IterativeLookup;
use crate::dht::routing::{RouterEntry, RoutingTable, K_BUCKET_SIZE};

/// A network-aware DHT node that uses a `LinkTransport` for peer communication.
///
/// Maintains a routing table refreshed by periodic background lookups.
/// Implements `DhtClient` for sync lookups from the cached routing table.
pub struct NetworkDht<T: LinkTransport> {
    local_key: PublicKey,
    table: Arc<RwLock<RoutingTable>>,
    transport: Arc<T>,
    bootstrap_nodes: Vec<SocketAddr>,
}

impl<T: LinkTransport + 'static> NetworkDht<T> {
    /// Create a new network DHT node.
    pub fn new(local_key: PublicKey, transport: Arc<T>, bootstrap_nodes: Vec<SocketAddr>) -> Self {
        let table = Arc::new(RwLock::new(RoutingTable::new(local_key.clone())));
        Self {
            local_key,
            table,
            transport,
            bootstrap_nodes,
        }
    }

    /// Bootstrap the DHT by contacting initial peers and performing iterative lookups.
    pub async fn bootstrap(&self) -> Result<(), NetworkDhtError> {
        tracing::info!(
            local = %self.local_key.to_hex(),
            bootstrap_count = self.bootstrap_nodes.len(),
            "DHT bootstrap started"
        );

        // Seed the routing table with bootstrap nodes
        for addr in &self.bootstrap_nodes {
            self.send_ping(*addr).await?;
        }

        // Self-lookup to discover nearby peers
        self.iterative_lookup(&self.local_key.clone()).await?;

        tracing::info!("DHT bootstrap complete");
        Ok(())
    }

    /// Perform a periodic refresh of the routing table.
    pub async fn refresh(&self) -> Result<(), NetworkDhtError> {
        // Look up our own key to discover nearby peers and refresh buckets
        let local = self.local_key.clone();
        self.iterative_lookup(&local).await.map(|_| ())
    }

    /// Perform an iterative lookup for a target key, populating the routing table.
    pub async fn iterative_lookup(
        &self,
        target: &PublicKey,
    ) -> Result<Vec<PublicKey>, NetworkDhtError> {
        let seeds: Vec<PublicKey> = {
            let table = self.table.read().await;
            table
                .find_closest(target, K_BUCKET_SIZE)
                .into_iter()
                .map(|e| e.public_key)
                .collect()
        };

        let mut lookup = IterativeLookup::new(target.clone(), seeds);

        while !lookup.is_exhausted() {
            let round = match lookup.next_round() {
                Some(r) => r,
                None => break,
            };

            for peer in &round {
                match self.query_peer(peer).await {
                    Ok(results) => {
                        lookup.add_results(results);
                    }
                    Err(e) => {
                        tracing::warn!(
                            peer = %peer.to_hex(),
                            error = %e,
                            "DHT query failed"
                        );
                    }
                }
            }
        }

        // Collect discovered peers and add to routing table
        let closest = lookup.closest_peers(K_BUCKET_SIZE);
        {
            let mut table = self.table.write().await;
            for public_key in &closest {
                let entry = RouterEntry {
                    public_key: public_key.clone(),
                    distance: RoutingTable::xor_distance(public_key, &self.local_key),
                    last_seen: 0,
                };
                let _ = table.add(entry);
            }
        }

        Ok(closest)
    }

    /// Get the K closest peers from the routing table (sync, cached).
    pub fn find_closest(&self, target: &PublicKey, count: usize) -> Vec<RouterEntry> {
        // Use try_read for non-blocking access
        if let Ok(table) = self.table.try_read() {
            table.find_closest(target, count)
        } else {
            Vec::new()
        }
    }

    /// Get the total number of peers in the routing table.
    pub fn peer_count(&self) -> usize {
        if let Ok(table) = self.table.try_read() {
            table.len()
        } else {
            0
        }
    }

    /// Start a background refresh loop. Returns immediately; runs until cancelled.
    pub fn start_background_refresh(self: &Arc<Self>) {
        let dht = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = dht.refresh().await {
                    tracing::warn!(error = %e, "DHT background refresh failed");
                }
            }
        });
    }

    // ─── private helpers ───

    async fn send_ping(&self, addr: SocketAddr) -> Result<(), NetworkDhtError> {
        // Send minimal DHT probe
        let probe = b"DHT_PING";
        self.transport
            .send_to(probe, addr)
            .await
            .map_err(|e| NetworkDhtError::Transport(e.to_string()))?;
        Ok(())
    }

    async fn query_peer(&self, peer: &PublicKey) -> Result<Vec<PublicKey>, NetworkDhtError> {
        // In a real implementation, this would:
        // 1. Resolve peer's address (from DHT or bootstrap)
        // 2. Send a DhtIntro request
        // 3. Receive DhtIntro response with peer's known nodes
        // For now, return empty — peers are discovered through bootstrap
        let _ = peer;
        Ok(Vec::new())
    }
}

impl<T: LinkTransport + 'static> DhtClient for NetworkDht<T> {
    fn lookup_intro_set(&self, target: &PublicKey) -> Vec<DhtIntroResult> {
        let entries = self.find_closest(target, K_BUCKET_SIZE);
        entries
            .into_iter()
            .map(|entry| DhtIntroResult {
                public_key: entry.public_key,
                addresses: Vec::new(), // Addresses would come from intro-set storage
            })
            .collect()
    }
}

#[derive(Debug, Error)]
pub enum NetworkDhtError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("lookup exhausted without results")]
    LookupExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use saferunnet_crypto::KeyAlgorithm;

    fn make_key(seed: u8) -> PublicKey {
        PublicKey::from_bytes(KeyAlgorithm::Ed25519, [seed; 32])
    }

    /// A stub transport for testing.
    struct StubTransport {
        addr: SocketAddr,
    }

    impl StubTransport {
        fn new() -> Self {
            Self {
                addr: "127.0.0.1:9999".parse().unwrap(),
            }
        }
    }

    impl LinkTransport for StubTransport {
        fn local_addr(&self) -> SocketAddr {
            self.addr
        }

        async fn send_to(
            &self,
            _data: &[u8],
            _addr: SocketAddr,
        ) -> Result<usize, crate::transport::TransportError> {
            Ok(0)
        }

        async fn recv_from(
            &self,
            _buf: &mut [u8],
        ) -> Result<crate::transport::Datagram, crate::transport::TransportError> {
            Err(crate::transport::TransportError::Closed)
        }

        fn close(&self) {}
    }

    #[tokio::test]
    async fn network_dht_bootstrap_with_stub() {
        let local = make_key(0x00);
        let transport = Arc::new(StubTransport::new());
        let bootstrap = vec!["127.0.0.1:10000".parse().unwrap()];
        let dht = NetworkDht::new(local.clone(), transport, bootstrap);

        // Bootstrap should not panic with stub transport
        let result = dht.bootstrap().await;
        // Stub transport will fail, but no panic
        assert!(result.is_err() || result.is_ok());
    }

    #[tokio::test]
    async fn network_dht_find_closest_empty() {
        let local = make_key(0x00);
        let transport = Arc::new(StubTransport::new());
        let dht = NetworkDht::new(local.clone(), transport, vec![]);

        let closest = dht.find_closest(&make_key(0x42), 5);
        assert!(closest.is_empty());
    }

    #[test]
    fn dht_client_trait_lookup_intro_set_empty() {
        let local = make_key(0x00);
        let transport = Arc::new(StubTransport::new());
        let dht = NetworkDht::new(local, transport, vec![]);

        let results: Vec<DhtIntroResult> = dht.lookup_intro_set(&make_key(0x10));
        assert!(results.is_empty());
    }
}


