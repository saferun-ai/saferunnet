use std::collections::HashMap;
use std::net::SocketAddr;

/// Pivot TX ID tracking for path alignment during path switches.
///
/// Lokinet C++ equivalent: BaseSession::_pivot_txid / _remote_pivot_txid
#[derive(Debug, Clone, Default)]
pub struct PivotTracker {
    pub local_txid: u64,
    pub remote_txid: u64,
    /// True if pivot is aligned with the remote side.
    pub aligned: bool,
}

/// Per-session TCP connection tracking.
#[derive(Debug, Clone)]
pub struct TcpHandle {
    pub local_port: u16,
    pub remote_addr: SocketAddr,
    pub connected: bool,
}

/// Per-session UDP socket handle.
#[derive(Debug, Clone)]
pub struct UdpHandle {
    pub local_port: u16,
    pub remote_addr: SocketAddr,
}

/// Session transport state: TCP + UDP handles + pivot tracking.
#[derive(Debug, Clone, Default)]
pub struct SessionTransport {
    pub pivot: PivotTracker,
    pub tcp_handles: HashMap<u16, TcpHandle>,
    pub udp_handles: HashMap<u16, UdpHandle>,
}

impl SessionTransport {
    pub fn new() -> Self { Self::default() }

    pub fn add_tcp(&mut self, port: u16, remote: SocketAddr) {
        self.tcp_handles.insert(port, TcpHandle { local_port: port, remote_addr: remote, connected: false });
    }

    pub fn add_udp(&mut self, port: u16, remote: SocketAddr) {
        self.udp_handles.insert(port, UdpHandle { local_port: port, remote_addr: remote });
    }

    pub fn tcp_connect(&mut self, port: u16) -> bool {
        if let Some(h) = self.tcp_handles.get_mut(&port) { h.connected = true; true } else { false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn test_pivot_default() { let p = PivotTracker::default(); assert_eq!(p.local_txid, 0); assert!(!p.aligned); }
    #[test] fn test_tcp_handle() { let mut t = SessionTransport::new(); t.add_tcp(8080, "10.0.0.1:9000".parse().unwrap()); assert_eq!(t.tcp_handles.len(), 1); }
    #[test] fn test_tcp_connect() { let mut t = SessionTransport::new(); t.add_tcp(8080, "10.0.0.1:9000".parse().unwrap()); assert!(t.tcp_connect(8080)); }
    #[test] fn test_udp_handle() { let mut t = SessionTransport::new(); t.add_udp(5353, "10.0.0.1:53".parse().unwrap()); assert_eq!(t.udp_handles.len(), 1); }
}
