use std::net::IpAddr;

use crate::net::IpPacket;
use super::policy::ExitPolicy;

/// Routes egress packets to the correct exit node based on exit policy.
pub struct EgressPacketRouter {
    exit_policy: Box<dyn ExitPolicy>,
    exit_nodes: Vec<(IpAddr, u16)>, // (exit_ip, exit_port)
}

impl EgressPacketRouter {
    pub fn new(policy: Box<dyn ExitPolicy>) -> Self {
        Self {
            exit_policy: policy,
            exit_nodes: Vec::new(),
        }
    }

    /// Add an exit node to the routing table.
    pub fn add_exit_node(&mut self, addr: IpAddr, port: u16) {
        self.exit_nodes.push((addr, port));
    }

    /// Number of registered exit nodes.
    pub fn exit_node_count(&self) -> usize {
        self.exit_nodes.len()
    }

    /// Pick the first exit node whose policy allows traffic to the
    /// packet`s destination. Returns `None` when no exit node matches.
    pub fn route_packet(&self, pkt: &IpPacket) -> Option<(IpAddr, u16)> {
        let dst = pkt.destination();
        let target = dst.ip().to_string();

        for &(exit_addr, exit_port) in &self.exit_nodes {
            if self.exit_policy.allows(&target, dst.port()).is_ok() {
                return Some((exit_addr, exit_port));
            }
        }
        None
    }

    /// Check whether ANY exit node would accept this packet.
    pub fn is_exit_allowed(&self, pkt: &IpPacket) -> bool {
        self.route_packet(pkt).is_some()
    }

    /// Get a reference to the exit policy.
    pub fn policy(&self) -> &dyn ExitPolicy {
        self.exit_policy.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::IpPacket;
    use super::super::policy::{AllowListPolicy, BlockAllPolicy, PermitAllPolicy};

    fn make_test_packet(dst: &str) -> IpPacket {
        let parts: Vec<&str> = dst.rsplitn(2, ':').collect();
        let ip: IpAddr = parts[1].parse().unwrap();
        let port: u16 = parts[0].parse().unwrap();
        let src = std::net::SocketAddr::new(ip, 12345);
        let dst_sa = std::net::SocketAddr::new(ip, port);
        // Build a minimal UDP packet for testing
        IpPacket::make_udp_packet(src, dst_sa, b"test").unwrap()
    }

    #[test]
    fn test_route_to_first_allowed_node() {
        let policy = PermitAllPolicy;
        let mut router = EgressPacketRouter::new(Box::new(policy));
        router.add_exit_node("10.0.0.1".parse().unwrap(), 1090);
        router.add_exit_node("10.0.0.2".parse().unwrap(), 1091);

        let pkt = make_test_packet("10.10.0.5:443");
        let result = router.route_packet(&pkt).unwrap();
        // Should pick the first node
        assert_eq!(result, ("10.0.0.1".parse::<IpAddr>().unwrap(), 1090));
    }

    #[test]
    fn test_route_respects_policy() {
        let policy = AllowListPolicy::new(vec![("192.168.1.100".into(), 80)]);
        let mut router = EgressPacketRouter::new(Box::new(policy));
        router.add_exit_node("10.0.0.1".parse().unwrap(), 1090);

        // Packet to 192.168.1.100:80 → allowed
        let pkt = make_test_packet("192.168.1.100:80");
        assert!(router.is_exit_allowed(&pkt));

        // Packet to 192.168.1.200:443 → denied
        let pkt2 = make_test_packet("192.168.1.200:443");
        assert!(!router.is_exit_allowed(&pkt2));
    }

    #[test]
    fn test_route_no_nodes_returns_none() {
        let policy = PermitAllPolicy;
        let router = EgressPacketRouter::new(Box::new(policy));
        let pkt = make_test_packet("10.0.0.1:80");
        assert!(router.route_packet(&pkt).is_none());
    }

    #[test]
    fn test_route_block_all_never_routes() {
        let policy = BlockAllPolicy;
        let mut router = EgressPacketRouter::new(Box::new(policy));
        router.add_exit_node("10.0.0.1".parse().unwrap(), 1090);

        let pkt = make_test_packet("192.168.1.1:443");
        assert!(router.route_packet(&pkt).is_none());
        assert!(!router.is_exit_allowed(&pkt));
    }

    #[test]
    fn test_add_multiple_nodes() {
        let policy = PermitAllPolicy;
        let mut router = EgressPacketRouter::new(Box::new(policy));
        assert_eq!(router.exit_node_count(), 0);
        router.add_exit_node("10.0.0.1".parse().unwrap(), 1090);
        router.add_exit_node("10.0.0.2".parse().unwrap(), 1091);
        router.add_exit_node("10.0.0.3".parse().unwrap(), 1092);
        assert_eq!(router.exit_node_count(), 3);
    }

    #[test]
    fn test_policy_accessor() {
        let policy = PermitAllPolicy;
        let router = EgressPacketRouter::new(Box::new(policy));
        let pkt = make_test_packet("10.0.0.1:80");
        // Just verify the policy ref can be used
        let dst = pkt.destination();
        assert!(router.policy().allows(&dst.ip().to_string(), dst.port()).is_ok());
    }
}
