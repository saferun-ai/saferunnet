pub mod mapping;
use std::net::{Ipv4Addr, Ipv6Addr};

/// IP network range for IPv4
#[derive(Debug, Clone)]
pub struct Ipv4Net {
    pub addr: Ipv4Addr,
    pub netmask: u8,
}

impl Ipv4Net {
    pub fn new(addr: Ipv4Addr, netmask: u8) -> Self {
        Self { addr, netmask }
    }

    pub fn contains(&self, other: &Ipv4Addr) -> bool {
        let mask = u32::MAX.wrapping_shl(32 - self.netmask as u32);
        let self_net = u32::from(self.addr) & mask;
        let other_net = u32::from(*other) & mask;
        self_net == other_net
    }
}

/// IP network range for IPv6
#[derive(Debug, Clone)]
pub struct Ipv6Net {
    pub addr: Ipv6Addr,
    pub netmask: u8,
}

/// Generate the next IPv4 in a network range
pub struct Ipv4RangeIterator {
    net: Ipv4Net,
    current: u32,
}

impl Ipv4RangeIterator {
    pub fn new(net: Ipv4Net) -> Self {
        let base = u32::from(net.addr);
        Self { net, current: base }
    }
}

impl Iterator for Ipv4RangeIterator {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        let mask = u32::MAX.wrapping_shl(32 - self.net.netmask as u32);
        let broadcast = u32::from(self.net.addr) | !mask;
        if self.current >= broadcast {
            return None;
        }
        self.current += 1;
        if self.current == u32::from(self.net.addr) {
            self.current += 1; // Skip network address
        }
        Some(Ipv4Addr::from(self.current))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ipv4_net_contains() {
        let net = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        assert!(net.contains(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!net.contains(&Ipv4Addr::new(10, 0, 1, 1)));
    }
}
