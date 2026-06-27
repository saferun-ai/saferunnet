use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::net::IpPacket;

/// Maps network addresses to local IPs for sessions.
/// Lokinet C++ equivalent: address_map<>
pub struct AddressMap<V> {
    map: HashMap<Vec<u8>, V>,
}

impl<V: Clone> AddressMap<V> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: &[u8], value: V) {
        self.map.insert(key.to_vec(), value);
    }

    pub fn get(&self, key: &[u8]) -> Option<&V> {
        self.map.get(key)
    }

    pub fn remove(&mut self, key: &[u8]) -> Option<V> {
        self.map.remove(key)
    }
}

/// TUN endpoint handler — processes inbound/outbound IP packets.
/// Lokinet C++ equivalent: llarp/handlers/tun.hpp TunEndpoint
pub struct TunEndpoint {
    pub ipv4_mapping: AddressMap<Ipv4Addr>,
    pub ipv6_mapping: AddressMap<Ipv6Addr>,
    pub exit_policy_allows_all: bool,
}

impl TunEndpoint {
    pub fn new() -> Self {
        Self {
            ipv4_mapping: AddressMap::new(),
            ipv6_mapping: AddressMap::new(),
            exit_policy_allows_all: true,
        }
    }

    /// Handle an outbound packet going OUT to the network
    pub fn handle_outbound_packet(&self, pkt: &IpPacket) -> bool {
        // Stub: always forward
        tracing::debug!(
            target: "handlers",
            "outbound: {} -> {}",
            pkt.source(),
            pkt.destination()
        );
        true
    }

    /// Handle an inbound packet coming IN from the network
    pub fn handle_inbound_packet(&self, pkt: &IpPacket) -> bool {
        tracing::debug!(
            target: "handlers",
            "inbound: {} -> {}",
            pkt.source(),
            pkt.destination()
        );
        true
    }

    /// Map a remote network address to a local IPv4
    pub fn map_session_to_local_ipv4(&mut self, remote: &[u8], ip: Ipv4Addr) {
        self.ipv4_mapping.insert(remote, ip);
    }

    /// Unmap a session
    pub fn unmap_session(&mut self, remote: &[u8]) {
        self.ipv4_mapping.remove(remote);
        self.ipv6_mapping.remove(remote);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_map() {
        let mut map = AddressMap::new();
        map.insert(b"node1", Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(map.get(b"node1"), Some(&Ipv4Addr::new(10, 0, 0, 1)));
        map.remove(b"node1");
        assert_eq!(map.get(b"node1"), None);
    }

    #[test]
    fn test_tun_endpoint_basic() {
        let mut ep = TunEndpoint::new();
        ep.map_session_to_local_ipv4(b"test-node", Ipv4Addr::new(172, 16, 0, 1));
        // Should not panic
        ep.unmap_session(b"test-node");
    }
}
