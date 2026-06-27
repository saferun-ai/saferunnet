use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::sync::mpsc;

/// An in-memory simulated network that routes datagrams between virtual addresses.
///
/// Each node registers a receiver channel. Sends are routed by address.
pub struct SimNetwork {
    nodes: HashMap<SocketAddr, mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>>,
}

impl SimNetwork {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// Register a node and get back a receiver for incoming datagrams.
    pub fn register(&mut self, addr: SocketAddr) -> mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.nodes.insert(addr, tx);
        rx
    }

    /// Send a datagram to a destination node.
    /// Returns true if delivered, false if destination unknown.
    pub fn send_to(&self, data: &[u8], from: SocketAddr, to: SocketAddr) -> bool {
        if let Some(tx) = self.nodes.get(&to) {
            let packet = (data.to_vec(), from);
            tx.send(packet).is_ok()
        } else {
            false
        }
    }

    /// Number of registered nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl Default for SimNetwork {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_network_routes_packets() {
        let mut net = SimNetwork::new();
        let addr_a: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:20000".parse().unwrap();

        let mut rx_b = net.register(addr_b);

        assert!(net.send_to(b"hello", addr_a, addr_b));
        assert!(!net.send_to(b"nobody", addr_a, "127.0.0.1:65535".parse().unwrap()));

        let (data, from) = rx_b.try_recv().unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(from, addr_a);
    }

    #[test]
    fn sim_network_node_count() {
        let mut net = SimNetwork::new();
        net.register("127.0.0.1:1".parse().unwrap());
        net.register("127.0.0.1:2".parse().unwrap());
        assert_eq!(net.node_count(), 2);
    }
}
