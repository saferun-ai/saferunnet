//! Onion forwarder for TUN packet routing.
//!
//! Wraps IP packets from the TUN device in onion layers and routes them
//! through the LLARP relay chain toward exit nodes.

use saferunnet_crypto::PublicKey;
use saferunnet_dns::resolver::DhtClient;
use saferunnet_link::{FrameKind, LlarpFrame};
use saferunnet_router::{OnionRouter, RelayHandler, RelayResult};
use std::net::SocketAddr;

/// Routes TUN packets through the onion network.
#[allow(dead_code)]
pub struct OnionForwarder {
    onion: OnionRouter,
    relay: RelayHandler,
}

impl OnionForwarder {
    pub fn new() -> Self {
        Self {
            onion: OnionRouter::new(),
            relay: RelayHandler::new(),
        }
    }

    /// Wrap an IP packet in onion layers and produce a relay-ready LLARP frame.
    pub fn wrap_packet(
        &self,
        packet: &[u8],
        path: &[PublicKey],
        nonce: &[u8; 32],
        path_id: u64,
    ) -> Result<LlarpFrame, ForwarderError> {
        if path.is_empty() {
            return Err(ForwarderError::EmptyPath);
        }
        if path.len() > saferunnet_router::onion::MAX_ONION_HOPS {
            return Err(ForwarderError::PathTooLong {
                hops: path.len(),
                max: saferunnet_router::onion::MAX_ONION_HOPS,
            });
        }

        let wrapped = self
            .onion
            .wrap(path, nonce, packet)
            .map_err(ForwarderError::Onion)?;

        LlarpFrame::new(FrameKind::RelayData, path_id, 0, wrapped).map_err(ForwarderError::Frame)
    }

    /// Process a relay frame at the current hop.
    #[allow(dead_code)]
    pub fn relay_hop(
        &self,
        frame: &LlarpFrame,
        hop_key: &PublicKey,
        nonce: &[u8; 32],
        total_hops: usize,
    ) -> Result<RelayResult, ForwarderError> {
        self.relay
            .handle_relay(frame, hop_key, nonce, total_hops)
            .map_err(ForwarderError::Relay)
    }

    /// Resolve a path through the DHT and forward an IP packet in one call.
    #[allow(dead_code)]
    pub fn resolve_and_forward(
        &self,
        packet: &[u8],
        dht: &dyn DhtClient,
        destination: &PublicKey,
        nonce: &[u8; 32],
        path_id: u64,
    ) -> Result<LlarpFrame, ForwarderError> {
        let path = self.find_path(dht, destination, 1, 3);
        self.wrap_packet(packet, &path, nonce, path_id)
    }

    /// Resolve a path through the DHT, return the wrapped frame and the first-hop address.
    pub fn resolve_and_forward_with_addr(
        &self,
        packet: &[u8],
        dht: &dyn DhtClient,
        destination: &PublicKey,
        nonce: &[u8; 32],
        path_id: u64,
    ) -> Result<(LlarpFrame, SocketAddr), ForwarderError> {
        let path = self.find_path(dht, destination, 1, 3);
        if path.is_empty() {
            return Err(ForwarderError::EmptyPath);
        }
        let first_hop_key = &path[0];
        let intro_results = dht.lookup_intro_set(first_hop_key);
        let first_addr: SocketAddr = intro_results
            .first()
            .and_then(|r| r.addresses.first())
            .and_then(|a| a.parse().ok())
            .ok_or(ForwarderError::NoAddress)?;
        let frame = self.wrap_packet(packet, &path, nonce, path_id)?;
        Ok((frame, first_addr))
    }

    /// Find the best path toward a destination through the DHT.
    pub fn find_path(
        &self,
        dht: &dyn DhtClient,
        destination: &PublicKey,
        _min_hops: usize,
        max_hops: usize,
    ) -> Vec<PublicKey> {
        let results = dht.lookup_intro_set(destination);
        let mut path: Vec<PublicKey> = results.into_iter().map(|r| r.public_key).collect();
        if path.len() > max_hops {
            path.truncate(max_hops);
        }
        path
    }
}

impl Default for OnionForwarder {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive a deterministic PublicKey from an IPv4 address (4 bytes).
#[allow(dead_code)]
pub(crate) fn derive_dest_key_from_ip(ip_bytes: &[u8]) -> PublicKey {
    let mut key_bytes = [0u8; 32];
    let copy_len = ip_bytes.len().min(32);
    key_bytes[..copy_len].copy_from_slice(&ip_bytes[..copy_len]);
    PublicKey::from_bytes(saferunnet_crypto::KeyAlgorithm::Ed25519, key_bytes)
}

#[derive(Debug, thiserror::Error)]
pub enum ForwarderError {
    #[error("empty path")]
    EmptyPath,
    #[error("path too long: {hops} hops, max {max}")]
    PathTooLong { hops: usize, max: usize },
    #[error("onion error: {0}")]
    Onion(#[from] saferunnet_router::OnionError),
    #[error("frame error: {0}")]
    Frame(#[from] saferunnet_link::FrameCodecError),
    #[error("relay error: {0}")]
    Relay(#[from] saferunnet_router::RelayError),
    #[error("no address found for first hop")]
    NoAddress,
}

#[cfg(test)]
mod tests {
    use super::*;
    use saferunnet_crypto::KeyAlgorithm;

    fn make_key(seed: u8) -> PublicKey {
        PublicKey::from_bytes(KeyAlgorithm::Ed25519, [seed; 32])
    }

    fn make_nonce(seed: u8) -> [u8; 32] {
        let mut n = [0u8; 32];
        n[0] = seed;
        n
    }

    #[test]
    fn forwarder_wrap_and_unwrap_through_path() {
        let fwd = OnionForwarder::new();
        let path: Vec<_> = (1..=3).map(make_key).collect();
        let nonce = make_nonce(42);
        let mut packet = Vec::new();
        saferunnet_exit::encode_exit_target("10.0.0.1", 443, &mut packet).unwrap();

        let frame = fwd.wrap_packet(&packet, &path, &nonce, 1).unwrap();
        assert_eq!(frame.kind, FrameKind::RelayData);
        assert_eq!(frame.path_id, 1);

        let mut current = frame;
        for (i, hop) in path.iter().enumerate() {
            let result = fwd.relay_hop(&current, hop, &nonce, path.len()).unwrap();
            match result {
                RelayResult::Forward { next_frame } => {
                    assert!(
                        i < path.len() - 1,
                        "intermediate hop should not be Exit at hop {i}"
                    );
                    current = next_frame;
                }
                RelayResult::Exit { plaintext } => {
                    assert_eq!(
                        i,
                        path.len() - 1,
                        "Exit should only occur at final hop, got at hop {i}"
                    );
                    assert_eq!(plaintext, packet);
                }
            }
        }
    }
    #[test]
    fn forwarder_rejects_empty_path() {
        let fwd = OnionForwarder::new();
        let result = fwd.wrap_packet(b"data", &[], &make_nonce(1), 1);
        assert!(result.is_err());
    }

    #[test]
    fn forwarder_rejects_too_many_hops() {
        let fwd = OnionForwarder::new();
        let path: Vec<_> = (0..10).map(make_key).collect();
        let result = fwd.wrap_packet(b"data", &path, &make_nonce(1), 1);
        assert!(result.is_err());
    }

    #[test]
    fn forwarder_find_path_from_dht() {
        struct StubDht;
        impl DhtClient for StubDht {
            fn lookup_intro_set(
                &self,
                _target: &PublicKey,
            ) -> Vec<saferunnet_dns::resolver::DhtIntroResult> {
                vec![
                    saferunnet_dns::resolver::DhtIntroResult {
                        public_key: make_key(1),
                        addresses: vec!["10.0.0.1:1090".into()],
                    },
                    saferunnet_dns::resolver::DhtIntroResult {
                        public_key: make_key(2),
                        addresses: vec!["10.0.0.2:1090".into()],
                    },
                    saferunnet_dns::resolver::DhtIntroResult {
                        public_key: make_key(3),
                        addresses: vec!["10.0.0.3:1090".into()],
                    },
                ]
            }
        }

        let fwd = OnionForwarder::new();
        let dest = make_key(99);
        let path = fwd.find_path(&StubDht, &dest, 1, 3);
        assert_eq!(path.len(), 3);
    }

    #[test]
    fn derive_dest_key_from_ip_consistent() {
        let ip = [10, 0, 0, 1u8];
        let key1 = derive_dest_key_from_ip(&ip);
        let key2 = derive_dest_key_from_ip(&ip);
        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn resolve_and_forward_wraps_into_llarp_frame() {
        struct StubDht;
        impl DhtClient for StubDht {
            fn lookup_intro_set(
                &self,
                _target: &PublicKey,
            ) -> Vec<saferunnet_dns::resolver::DhtIntroResult> {
                vec![saferunnet_dns::resolver::DhtIntroResult {
                    public_key: make_key(1),
                    addresses: vec!["10.0.0.1:1090".into()],
                }]
            }
        }

        let fwd = OnionForwarder::new();
        let dest = make_key(99);
        let nonce = make_nonce(42);
        let packet = b"TUN IP packet";

        let frame = fwd
            .resolve_and_forward(packet, &StubDht, &dest, &nonce, 1)
            .unwrap();
        assert_eq!(frame.kind, FrameKind::RelayData);
        assert_eq!(frame.path_id, 1);
    }

    #[test]
    fn resolve_and_forward_empty_dht_returns_empty_path() {
        struct EmptyDht;
        impl DhtClient for EmptyDht {
            fn lookup_intro_set(
                &self,
                _target: &PublicKey,
            ) -> Vec<saferunnet_dns::resolver::DhtIntroResult> {
                vec![]
            }
        }

        let fwd = OnionForwarder::new();
        let dest = make_key(99);
        let nonce = make_nonce(42);
        let packet = b"TUN IP packet";

        let result = fwd.resolve_and_forward(packet, &EmptyDht, &dest, &nonce, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ForwarderError::EmptyPath));
    }

    #[test]
    fn resolve_and_forward_with_addr_returns_frame_and_address() {
        struct StubDht;
        impl DhtClient for StubDht {
            fn lookup_intro_set(
                &self,
                _target: &PublicKey,
            ) -> Vec<saferunnet_dns::resolver::DhtIntroResult> {
                vec![saferunnet_dns::resolver::DhtIntroResult {
                    public_key: make_key(1),
                    addresses: vec!["10.0.0.1:1090".into()],
                }]
            }
        }

        let fwd = OnionForwarder::new();
        let dest = make_key(99);
        let nonce = make_nonce(42);
        let packet = b"TUN IP packet";

        let (frame, addr) = fwd
            .resolve_and_forward_with_addr(packet, &StubDht, &dest, &nonce, 1)
            .unwrap();
        assert_eq!(frame.kind, FrameKind::RelayData);
        assert_eq!(frame.path_id, 1);
        assert_eq!(addr, "10.0.0.1:1090".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn resolve_and_forward_with_addr_no_addresses_returns_error() {
        struct NoAddrDht;
        impl DhtClient for NoAddrDht {
            fn lookup_intro_set(
                &self,
                _target: &PublicKey,
            ) -> Vec<saferunnet_dns::resolver::DhtIntroResult> {
                vec![saferunnet_dns::resolver::DhtIntroResult {
                    public_key: make_key(1),
                    addresses: vec![],
                }]
            }
        }

        let fwd = OnionForwarder::new();
        let dest = make_key(99);
        let nonce = make_nonce(42);
        let packet = b"TUN IP packet";

        let result = fwd.resolve_and_forward_with_addr(packet, &NoAddrDht, &dest, &nonce, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ForwarderError::NoAddress));
    }
}
