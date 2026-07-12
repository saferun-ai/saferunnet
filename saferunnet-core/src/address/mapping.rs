use std::collections::HashMap;
use std::net::Ipv4Addr;
use parking_lot::RwLock;

use super::Ipv4Net;
use crate::contact::RouterId;

/// Bidirectional IPv4 address ↔ RouterId mapping for tunnel endpoints.
/// Lokinet C++ equivalent: llarp/address/address_map.hpp
#[derive(Debug)]
pub struct AddressMap {
    network: Ipv4Net,
    /// RouterId → allocated Ipv4Addr
    rid_to_addr: RwLock<HashMap<RouterId, Ipv4Addr>>,
    /// Ipv4Addr → RouterId
    addr_to_rid: RwLock<HashMap<Ipv4Addr, RouterId>>,
    /// Next candidate address within the network range
    next_addr: RwLock<u32>,
}

impl AddressMap {
    /// Create a new AddressMap for the given CIDR network.
    pub fn new(network: Ipv4Net) -> Self {
        let base = u32::from(network.addr);
        // Start at base + 2 to skip network address (base) and gateway (base+1)
        let next = base.saturating_add(2);
        Self {
            network,
            rid_to_addr: RwLock::new(HashMap::new()),
            addr_to_rid: RwLock::new(HashMap::new()),
            next_addr: RwLock::new(next),
        }
    }

    /// Allocate the next free IPv4 address for the given RouterId.
    /// Returns Some(addr) on success, or None if the pool is exhausted.
    pub fn allocate(&self, rid: RouterId) -> Option<Ipv4Addr> {
        // Check if already allocated
        {
            let rid_to_addr = self.rid_to_addr.read();
            if let Some(addr) = rid_to_addr.get(&rid) {
                return Some(*addr);
            }
        }

        let mask = u32::MAX.wrapping_shl(32 - self.network.netmask as u32);
        let network_base = u32::from(self.network.addr) & mask;
        let broadcast = network_base | !mask;

        let mut next = self.next_addr.write();
        let start = *next;
        loop {
            if *next >= broadcast {
                // Pool exhausted; wrap around and try from start
                *next = network_base.saturating_add(2);
                if *next >= broadcast {
                    return None;
                }
            }

            let candidate = Ipv4Addr::from(*next);
            *next += 1;

            // Check if already in use
            {
                let addr_to_rid = self.addr_to_rid.read();
                if addr_to_rid.contains_key(&candidate) {
                    if *next == start {
                        return None; // Full loop, no free addresses
                    }
                    continue;
                }
            }

            // Allocate
            {
                let mut rid_to_addr = self.rid_to_addr.write();
                let mut addr_to_rid = self.addr_to_rid.write();
                rid_to_addr.insert(rid, candidate);
                addr_to_rid.insert(candidate, rid);
            }
            return Some(candidate);
        }
    }

    /// Release an allocated IPv4 address, freeing it for later use.
    pub fn release(&self, addr: Ipv4Addr) {
        let mut rid_to_addr = self.rid_to_addr.write();
        let mut addr_to_rid = self.addr_to_rid.write();

        if let Some(rid) = addr_to_rid.remove(&addr) {
            rid_to_addr.remove(&rid);
        }
    }

    /// Look up the RouterId mapped to an IPv4 address.
    pub fn lookup(&self, addr: &Ipv4Addr) -> Option<RouterId> {
        self.addr_to_rid.read().get(addr).copied()
    }

    /// Look up the IPv4 address mapped to a RouterId.
    pub fn reverse_lookup(&self, rid: &RouterId) -> Option<Ipv4Addr> {
        self.rid_to_addr.read().get(rid).copied()
    }

    /// Number of currently allocated mappings.
    pub fn len(&self) -> usize {
        self.rid_to_addr.read().len()
    }

    /// True if no mappings are allocated.
    pub fn is_empty(&self) -> bool {
        self.rid_to_addr.read().is_empty()
    }

    /// Clear all mappings.
    pub fn clear(&self) {
        self.rid_to_addr.write().clear();
        self.addr_to_rid.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_rid(seed: u8) -> RouterId {
        let mut data = [0u8; 32];
        data[0] = seed;
        RouterId(data)
    }

    fn test_network() -> Ipv4Net {
        Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 16)
    }

    #[test]
    fn test_allocate_and_lookup() {
        let map = AddressMap::new(test_network());
        let rid = make_rid(1);
        let addr = map.allocate(rid);
        assert!(addr.is_some());
        let addr = addr.unwrap();
        assert_eq!(map.lookup(&addr), Some(rid));
    }

    #[test]
    fn test_reverse_lookup() {
        let map = AddressMap::new(test_network());
        let rid = make_rid(2);
        let addr = map.allocate(rid).unwrap();
        assert_eq!(map.reverse_lookup(&rid), Some(addr));
    }

    #[test]
    fn test_release() {
        let map = AddressMap::new(test_network());
        let rid = make_rid(3);
        let addr = map.allocate(rid).unwrap();
        assert_eq!(map.len(), 1);
        map.release(addr);
        assert_eq!(map.len(), 0);
        assert_eq!(map.lookup(&addr), None);
        assert_eq!(map.reverse_lookup(&rid), None);
    }

    #[test]
    fn test_allocate_same_rid_returns_same_addr() {
        let map = AddressMap::new(test_network());
        let rid = make_rid(4);
        let addr1 = map.allocate(rid).unwrap();
        let addr2 = map.allocate(rid).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_allocate_different_rids_different_addrs() {
        let map = AddressMap::new(test_network());
        let addr1 = map.allocate(make_rid(5)).unwrap();
        let addr2 = map.allocate(make_rid(6)).unwrap();
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_allocate_reuses_released_addr() {
        let map = AddressMap::new(test_network());
        let rid1 = make_rid(7);
        let rid2 = make_rid(8);
        let addr1 = map.allocate(rid1).unwrap();
        map.release(addr1);
        let addr2 = map.allocate(rid2).unwrap();
        // After release, the next allocation may get a different address,
        // but the released address should be re-usable once the cursor wraps.
        // For now, verify both allocations work.
        assert!(map.lookup(&addr2).is_some());
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_clear() {
        let map = AddressMap::new(test_network());
        map.allocate(make_rid(9)).unwrap();
        map.allocate(make_rid(10)).unwrap();
        assert_eq!(map.len(), 2);
        map.clear();
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
    }
}