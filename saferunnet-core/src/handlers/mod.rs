use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use std::path::Path;

use crate::address::{Ipv4Net, Ipv6Net};
use crate::net::IpPacket;
use crate::vpn::policy::ExitPolicy;
use crate::dns::message::DnsMessage;
use crate::dns::resolver::LokiResolver;
use crate::dns::resolver::is_saferunnet_name;
use crate::dns::server::{LOKI_TUN_GATEWAY, DEFAULT_TTL};
use thiserror::Error;
use tracing;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur inside the TUN handler layer.
#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN interface not configured")]
    NotConfigured,

    #[error("TUN interface is not running")]
    NotRunning,

    #[error("DNS server setup failed: {0}")]
    DnsSetup(String),

    #[error("IPv4 address pool exhausted for {0:?}")]
    Ipv4PoolExhausted(Ipv4Net),

    #[error("IPv6 address pool exhausted for {0:?}")]
    Ipv6PoolExhausted(Ipv6Net),

    #[error("failed to persist IP mappings: {0}")]
    PersistError(String),

    #[error("IPv6 is not enabled on this endpoint")]
    Ipv6NotEnabled,

    #[error("exit policy denied traffic to {target}:{port}")]
    ExitPolicyDenied { target: String, port: u16 },

    #[error("packet is malformed or truncated")]
    MalformedPacket,

    #[error("no active path for remote session")]
    NoActivePath,

    #[error("internal handler error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TunEndpointBase — abstract TUN endpoint interface
// ---------------------------------------------------------------------------

/// Abstract TUN endpoint interface for platform-independent I/O.
/// Lokinet C++ equivalent: `llarp/handlers/tun_base.hpp` `TunEPBase`.
pub trait TunEndpointBase {
    /// Write an IP packet to the TUN device.
    fn write_packet(&self, pkt: &[u8]) -> Result<usize, TunError>;
    
    /// Read an IP packet from the TUN device (blocking).
    fn read_packet(&self) -> Result<Vec<u8>, TunError>;
    
    /// Return the TUN interface name.
    fn if_name(&self) -> &str;
    
    /// Return whether the endpoint is currently running.
    fn is_running(&self) -> bool;
    
    /// Close the TUN device and stop processing.
    fn close(&mut self) -> Result<(), TunError>;
}
// Traffic-type constants (port from Lokinet C++)
// ---------------------------------------------------------------------------

/// Lokinet-style traffic-type identifiers used when sending data over a path.
pub mod traffic_type {
    /// UDP over lokinet (session-based)
    pub const UDP: u8 = 0;
    /// TCP over lokinet (session-based)
    pub const TCP: u8 = 1;
    /// Raw IP (e.g. ICMP) — no session
    pub const RAW: u8 = 2;
    /// QUIC tunneled inside a lokinet session
    pub const TUNNELED_QUIC: u8 = 3;
}

// ---------------------------------------------------------------------------
// AddressMap — retained from the original stub
// ---------------------------------------------------------------------------

/// Maps network addresses to local IPs for sessions.
/// Lokinet C++ equivalent: `address_map<>`
#[derive(Debug, Clone)]
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

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ---------------------------------------------------------------------------
// SessionEntry — bookkeeping for each active session
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SessionEntry {
    created: Instant,
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
}

// ---------------------------------------------------------------------------
// TunEndpoint
// ---------------------------------------------------------------------------

/// TUN endpoint handler — processes inbound/outbound IP packets.
///
/// Ported from Lokinet C++: `llarp/handlers/tun.hpp` `TunEndpoint`.
///
/// The endpoint owns a pool of local IPv4 (and optionally IPv6) addresses
/// carved out of the configured network. Every remote session gets a unique
/// local address mapped into the TUN interface so that the OS kernel sees
/// normal socket endpoints.
pub struct TunEndpoint {
    // ── Network configuration ──────────────────────────────────────────
    pub local_net: Ipv4Net,
    pub local_ipv6_net: Option<Ipv6Net>,
    pub ipv6_enabled: bool,
    pub if_name: String,
    pub path_alignment_timeout: Duration,

    // ── Exit policy ────────────────────────────────────────────────────
    pub exit_policy: Option<Box<dyn ExitPolicy>>,

    // ── DNS resolver ──────────────────────────────────────────────────
    pub resolver: Option<Box<dyn LokiResolver>>,

    // ── IP address mappings ────────────────────────────────────────────
    pub ipv4_mapping: AddressMap<Ipv4Addr>,
    pub ipv6_mapping: AddressMap<Ipv6Addr>,

    // ── Internal state ─────────────────────────────────────────────────
    sessions: HashMap<Vec<u8>, SessionEntry>,
    assigned_ipv4: HashSet<Ipv4Addr>,
    assigned_ipv6: HashSet<Ipv6Addr>,
    running: bool,
}

impl TunEndpoint {
    // ── Construction ───────────────────────────────────────────────────

    /// Create a new `TunEndpoint` bound to a specific IPv4 subnet.
    ///
    /// The first usable address in `local_net` is reserved as the TUN
    /// interface''s own IP (returned by [`get_ipv4`]).
    pub fn new(local_net: Ipv4Net, if_name: String) -> Self {
        Self {
            local_net,
            local_ipv6_net: None,
            ipv6_enabled: false,
            if_name,
            path_alignment_timeout: Duration::from_secs(30),
            exit_policy: None,
            resolver: None,
            ipv4_mapping: AddressMap::new(),
            ipv6_mapping: AddressMap::new(),
            sessions: HashMap::new(),
            assigned_ipv4: HashSet::new(),
            assigned_ipv6: HashSet::new(),
            running: false,
        }
    }

    // ── Lifecycle ──────────────────────────────────────────────────────

    /// Initialise the TUN interface and start the DNS server.
    ///
    /// This is a stub — the actual platform-specific TUN setup lives in
    /// `saferunnet-platform`.
    pub fn configure(&mut self) -> Result<(), TunError> {
        tracing::info!(
            target: "handlers",
            local_net = ?self.local_net,
            if_name = %self.if_name,
            "configuring TUN endpoint"
        );
        self.setup_dns()?;
        self.running = true;
        Ok(())
    }

    /// Start the DNS server bound to the TUN interface.
    pub fn setup_dns(&mut self) -> Result<(), TunError> {
        tracing::info!(
            target: "handlers",
            if_name = %self.if_name,
            "setting up DNS server"
        );
        Ok(())
    }

    /// Periodic maintenance — expire stale session mappings.
    pub fn tick_tun(&mut self, now: Duration) {
        let deadline = Instant::now()
            .checked_sub(self.path_alignment_timeout)
            .unwrap_or(Instant::now());

        let expired: Vec<Vec<u8>> = self
            .sessions
            .iter()
            .filter(|(_k, v)| v.created < deadline)
            .map(|(k, _v)| k.clone())
            .collect();

        for key in &expired {
            self.remove_session(key);
        }

        if !expired.is_empty() {
            tracing::debug!(
                target: "handlers",
                count = expired.len(),
                "expired stale TUN sessions"
            );
        }

        let _ = now;
    }

    /// Shut down the TUN interface and DNS server.
    pub fn stop(&mut self) -> Result<(), TunError> {
        tracing::info!(
            target: "handlers",
            if_name = %self.if_name,
            "stopping TUN endpoint"
        );
        self.sessions.clear();
        self.assigned_ipv4.clear();
        self.assigned_ipv6.clear();
        self.ipv4_mapping = AddressMap::new();
        self.ipv6_mapping = AddressMap::new();
        self.running = false;
        Ok(())
    }

    // ── Packet handlers ────────────────────────────────────────────────

    /// Handle a packet going **outbound** (from the TUN toward the network).
    pub fn handle_outbound_packet(&self, pkt: &IpPacket) -> Result<(), TunError> {
        if !self.running {
            return Err(TunError::NotRunning);
        }

        tracing::debug!(
            target: "handlers",
            src = %pkt.source(),
            dst = %pkt.destination(),
            proto = ?pkt.protocol(),
            "outbound packet"
        );

        if !self.is_allowing_traffic(pkt) {
            return Err(TunError::ExitPolicyDenied {
                target: format!("{}", pkt.destination().ip()),
                port: pkt.destination().port(),
            });
        }

        Ok(())
    }

    /// Handle a packet coming **inbound** (from the network toward the TUN).
    pub fn handle_inbound_packet(&self, pkt: &IpPacket, remote: &[u8]) -> Result<(), TunError> {
        if !self.running {
            return Err(TunError::NotRunning);
        }

        tracing::debug!(
            target: "handlers",
            src = %pkt.source(),
            dst = %pkt.destination(),
            proto = ?pkt.protocol(),
            remote_len = remote.len(),
            "inbound packet"
        );

        let sess = self.sessions.get(remote).ok_or(TunError::NoActivePath)?;

        let _ = sess;
        Ok(())
    }

    // ── IP address management ──────────────────────────────────────────

    /// Assign a local IPv4 address to a remote session and return it.
    ///
    /// Freed IPs are reused first. Returns `None` when the pool is exhausted.
    pub fn map_session_to_local_ipv4(&mut self, remote: &[u8]) -> Option<Ipv4Addr> {
        let mask = u32::MAX.wrapping_shl(32 - self.local_net.netmask as u32);
        let network = u32::from(self.local_net.addr) & mask;
        let broadcast = network | !mask;
        let iface_ip = u32::from(self.local_net.addr);

        // If a session already exists (e.g. created by IPv6 mapping), sync v4.
        if let Some(entry) = self.sessions.get(remote) {
            let ipv4 = entry.ipv4;
            if !self.assigned_ipv4.contains(&ipv4) {
                self.assigned_ipv4.insert(ipv4);
                self.ipv4_mapping.insert(remote, ipv4);
            }
            return Some(ipv4);
        }

        // Full-range scan, skipping network, broadcast, and interface IPs.
        for idx in (network + 1)..broadcast {
            if idx == iface_ip {
                continue;
            }
            let candidate = Ipv4Addr::from(idx);
            if !self.assigned_ipv4.contains(&candidate) {
                return self.commit_ipv4(remote, candidate);
            }
        }

        None
    }

    fn commit_ipv4(&mut self, remote: &[u8], ip: Ipv4Addr) -> Option<Ipv4Addr> {
        self.assigned_ipv4.insert(ip);
        self.ipv4_mapping.insert(remote, ip);
        self.sessions.insert(
            remote.to_vec(),
            SessionEntry {
                created: Instant::now(),
                ipv4: ip,
                ipv6: None,
            },
        );
        tracing::debug!(
            target: "handlers",
            ?ip,
            remote_len = remote.len(),
            "mapped IPv4 session"
        );
        Some(ip)
    }

    /// Assign a local IPv6 address to a remote session (requires `ipv6_enabled`).
    pub fn map_session_to_local_ipv6(&mut self, remote: &[u8]) -> Option<Ipv6Addr> {
        if !self.ipv6_enabled {
            return None;
        }

        let ipv6_net = self.local_ipv6_net.as_ref()?;

        if let Some(entry) = self.sessions.get(remote) {
            return entry.ipv6;
        }

        let net_bytes = ipv6_net.addr.octets();
        let prefix_len = ipv6_net.netmask as usize;

        for host_id in 1u8..=255u8 {
            let mut addr_bytes = net_bytes;
            let byte_idx = prefix_len / 8;
            if byte_idx < 16 {
                addr_bytes[byte_idx] = host_id;
            }
            let candidate = Ipv6Addr::from(addr_bytes);

            if !self.assigned_ipv6.contains(&candidate) {
                self.assigned_ipv6.insert(candidate);
                self.ipv6_mapping.insert(remote, candidate);

                let entry = self.sessions.get_mut(remote);
                if let Some(e) = entry {
                    e.ipv6 = Some(candidate);
                } else {
                    self.sessions.insert(
                        remote.to_vec(),
                        SessionEntry {
                            created: Instant::now(),
                            ipv4: self.local_net.addr,
                            ipv6: Some(candidate),
                        },
                    );
                }

                tracing::debug!(
                    target: "handlers",
                    ?candidate,
                    "mapped IPv6 session"
                );

                return Some(candidate);
            }
        }

        None
    }

    /// Remove a session and release its IP addresses back to the pool.
    pub fn unmap_session(&mut self, remote: &[u8]) {
        if let Some(entry) = self.sessions.remove(remote) {
            self.assigned_ipv4.remove(&entry.ipv4);
            if let Some(v6) = entry.ipv6 {
                self.assigned_ipv6.remove(&v6);
            }
            self.ipv4_mapping.remove(remote);
            self.ipv6_mapping.remove(remote);
            tracing::debug!(
                target: "handlers",
                remote_len = remote.len(),
                "unmapped session"
            );
        }
    }

    /// Return the mapped local IPs (IPv4, IPv6) for a remote session.
    pub fn get_mapped_ip(&self, remote: &[u8]) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
        let v4 = self.ipv4_mapping.get(remote).copied();
        let v6 = self.ipv6_mapping.get(remote).copied();
        (v4, v6)
    }

    // ── Traffic policy ─────────────────────────────────────────────────

    /// Check whether `pkt` is allowed under the current exit policy.
    ///
    /// Returns `true` when there is no exit policy (i.e. not an exit node)
    /// or when the policy explicitly permits the traffic.
    pub fn is_allowing_traffic(&self, pkt: &IpPacket) -> bool {
        let policy = match &self.exit_policy {
            Some(p) => p,
            None => return true,
        };

        let target = format!("{}", pkt.destination().ip());
        let port = pkt.destination().port();

        policy.allows(&target, port).is_ok()
    }

    // ── Helpers ────────────────────────────────────────────────────────

    /// The local IPv4 address of this TUN endpoint (the interface''s own IP).
    pub fn get_ipv4(&self) -> Ipv4Addr {
        self.local_net.addr
    }

    /// The local IPv6 address of this TUN endpoint, if IPv6 is enabled.
    pub fn get_ipv6(&self) -> Option<Ipv6Addr> {
        self.local_ipv6_net.as_ref().map(|n| n.addr)
    }

    /// Whether IPv6 is enabled on this endpoint.
    pub fn supports_ipv6(&self) -> bool {
        self.ipv6_enabled
    }

    /// Returns `true` when this endpoint is a service node.
    ///
    /// Stub: always returns `false` for now.
    pub fn is_service_node(&self) -> bool {
        false
    }

    /// Returns `true` when this endpoint is an exit node
    /// (i.e. has an active exit policy configured).
    pub fn is_exit_node(&self) -> bool {
        self.exit_policy.is_some()
    }

    /// Whether the endpoint has been configured and is running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    // ── Internal helpers ───────────────────────────────────────────────

    fn remove_session(&mut self, remote: &[u8]) {
        if let Some(entry) = self.sessions.remove(remote) {
            self.assigned_ipv4.remove(&entry.ipv4);
            if let Some(v6) = entry.ipv6 {
                self.assigned_ipv6.remove(&v6);
            }
            self.ipv4_mapping.remove(remote);
            self.ipv6_mapping.remove(remote);
        }
    }

    // ── DNS hook ───────────────────────────────────────────────────────

    /// Hook for .loki DNS resolution.
    /// If the query contains a .loki name, resolve it and synthesize an A record response.
    /// Returns None if the query does not contain a .loki name.
    pub fn hook_dns_query(&self, msg: &DnsMessage) -> Option<DnsMessage> {
        let has_loki = msg.questions.iter().any(|q| is_saferunnet_name(&q.name));
        if !has_loki {
            return None;
        }

        let mut response = DnsMessage::response_from(msg);

        if self.resolver.is_none() {
            for q in &msg.questions {
                if is_saferunnet_name(&q.name) {
                    response.add_a_answer(&q.name, LOKI_TUN_GATEWAY, DEFAULT_TTL);
                }
            }
            return Some(response);
        }

        let resolver = self.resolver.as_ref().unwrap();
        let mut all_resolved = true;
        for q in &msg.questions {
            if !is_saferunnet_name(&q.name) {
                continue;
            }
            match resolver.resolve(&q.name) {
                Ok(pks) if !pks.is_empty() => {
                    response.add_a_answer(&q.name, LOKI_TUN_GATEWAY, DEFAULT_TTL);
                }
                _ => {
                    all_resolved = false;
                }
            }
        }

        if !all_resolved && response.answers.is_empty() {
            response.add_nx_reply();
        }

        Some(response)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn::policy::{AllowListPolicy, PermitAllPolicy};

    fn test_net() -> Ipv4Net {
        Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 24)
    }

    fn make_ipv4_pkt(src: &str, dst: &str) -> IpPacket {
        let data = build_ipv4_header(
            src.parse::<Ipv4Addr>().unwrap(),
            dst.parse::<Ipv4Addr>().unwrap(),
            6,
        );
        IpPacket::new(data).unwrap()
    }

    fn build_ipv4_header(src: Ipv4Addr, dst: Ipv4Addr, proto: u8) -> Vec<u8> {
        let mut hdr = vec![0u8; 20];
        hdr[0] = 0x45;
        hdr[2] = 0x00;
        hdr[3] = 0x14;
        hdr[9] = proto;
        hdr[12..16].copy_from_slice(&src.octets());
        hdr[16..20].copy_from_slice(&dst.octets());
        hdr
    }

    // ── Test: TunEndpoint creation with defaults ───────────────────────

    #[test]
    fn test_tun_endpoint_creation() {
        let ep = TunEndpoint::new(test_net(), "lokitun0".into());
        assert_eq!(ep.get_ipv4(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ep.if_name, "lokitun0");
        assert!(!ep.supports_ipv6());
        assert!(!ep.is_exit_node());
        assert!(!ep.is_service_node());
        assert!(!ep.is_running());
        assert_eq!(ep.path_alignment_timeout, Duration::from_secs(30));
    }

    // ── Test: IPv4 session mapping / unmapping ─────────────────────────

    #[test]
    fn test_ipv4_session_mapping() {
        let mut ep = TunEndpoint::new(test_net(), "tun0".into());
        let remote = b"node-aaaa";

        let ip = ep.map_session_to_local_ipv4(remote);
        assert!(ip.is_some());
        let ip = ip.unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 2));

        // Same remote should return the same IP.
        let ip2 = ep.map_session_to_local_ipv4(remote);
        assert_eq!(ip2, Some(ip));

        // Unmap and verify IP is released.
        ep.unmap_session(remote);
        assert_eq!(ep.ipv4_mapping.get(remote), None);
        assert!(!ep.assigned_ipv4.contains(&ip));
    }

    // ── Test: IPv6 session mapping (when enabled) ──────────────────────

    #[test]
    fn test_ipv6_session_mapping() {
        let mut ep = TunEndpoint::new(test_net(), "tun0".into());
        ep.ipv6_enabled = true;
        ep.local_ipv6_net = Some(Ipv6Net {
            addr: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            netmask: 64,
        });

        let remote = b"node-bbbb";
        let ip6 = ep.map_session_to_local_ipv6(remote);
        assert!(ip6.is_some());

        let v4 = ep.map_session_to_local_ipv4(remote).unwrap();
        let (got_v4, got_v6) = ep.get_mapped_ip(remote);
        assert_eq!(got_v4, Some(v4));
        assert!(got_v6.is_some());
    }

    // ── Test: IPv6 disabled ────────────────────────────────────────────

    #[test]
    fn test_ipv6_disabled_returns_none() {
        let mut ep = TunEndpoint::new(test_net(), "tun0".into());
        assert!(!ep.supports_ipv6());
        assert_eq!(ep.get_ipv6(), None);

        let ip6 = ep.map_session_to_local_ipv6(b"any");
        assert_eq!(ip6, None);
    }

    // ── Test: IP collision detection ───────────────────────────────────

    #[test]
    fn test_ipv4_collision_detection() {
        let mut ep = TunEndpoint::new(test_net(), "tun0".into());

        let ip1 = ep.map_session_to_local_ipv4(b"node1").unwrap();
        let ip2 = ep.map_session_to_local_ipv4(b"node2").unwrap();
        assert_ne!(ip1, ip2);

        assert!(ep.assigned_ipv4.contains(&ip1));
        assert!(ep.assigned_ipv4.contains(&ip2));

        // Unmap node1 — its IP should be reusable.
        ep.unmap_session(b"node1");
        assert!(!ep.assigned_ipv4.contains(&ip1));

        let ip3 = ep.map_session_to_local_ipv4(b"node3").unwrap();
        assert_eq!(ip3, ip1);
    }

    // ── Test: Exit policy traffic filtering ────────────────────────────

    #[test]
    fn test_exit_policy_allows_traffic() {
        let mut ep = TunEndpoint::new(test_net(), "tun0".into());

        // No exit policy → allows everything.
        let pkt = make_ipv4_pkt("10.0.0.2", "8.8.8.8");
        assert!(ep.is_allowing_traffic(&pkt));
        assert!(!ep.is_exit_node());

        // Set allow-list policy → exit node.
        ep.exit_policy = Some(Box::new(AllowListPolicy::new(vec![("8.8.8.8".into(), 0)])));
        assert!(ep.is_exit_node());
        assert!(ep.is_allowing_traffic(&pkt));

        // Blocked destination.
        let blocked = make_ipv4_pkt("10.0.0.3", "1.1.1.1");
        assert!(!ep.is_allowing_traffic(&blocked));
    }

    #[test]
    fn test_permit_all_exit_policy() {
        let mut ep = TunEndpoint::new(test_net(), "tun0".into());
        ep.exit_policy = Some(Box::new(PermitAllPolicy));
        assert!(ep.is_exit_node());

        let pkt = make_ipv4_pkt("10.0.0.2", "8.8.8.8");
        assert!(ep.is_allowing_traffic(&pkt));
    }

    // ── Test: handle_outbound_packet with exit policy denial ───────────

    #[test]
    fn test_outbound_packet_exit_denial() {
        let mut ep = TunEndpoint::new(test_net(), "tun0".into());
        ep.configure().unwrap();
        ep.exit_policy = Some(Box::new(AllowListPolicy::new(vec![])));

        let pkt = make_ipv4_pkt("10.0.0.2", "8.8.8.8");
        let result = ep.handle_outbound_packet(&pkt);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TunError::ExitPolicyDenied { .. }
        ));
    }

    #[test]
    fn test_outbound_packet_not_running() {
        let ep = TunEndpoint::new(test_net(), "tun0".into());
        let pkt = make_ipv4_pkt("10.0.0.2", "8.8.8.8");
        let result = ep.handle_outbound_packet(&pkt);
        assert!(matches!(result.unwrap_err(), TunError::NotRunning));
    }

    // ── Test: tick_tun cleanup of expired sessions ─────────────────────

    #[test]
    fn test_tick_tun_expires_sessions() {
        let mut ep = TunEndpoint::new(test_net(), "tun0".into());
        ep.path_alignment_timeout = Duration::from_millis(1);

        let ip = ep.map_session_to_local_ipv4(b"node-expire").unwrap();
        assert!(ep.ipv4_mapping.get(b"node-expire").is_some());

        std::thread::sleep(Duration::from_millis(10));
        ep.tick_tun(Duration::from_secs(1));
        assert!(ep.ipv4_mapping.get(b"node-expire").is_none());
        assert!(!ep.assigned_ipv4.contains(&ip));
    }

    // ── Test: lifecycle configure / stop ───────────────────────────────

    #[test]
    fn test_lifecycle_configure_stop() {
        let mut ep = TunEndpoint::new(test_net(), "tun0".into());
        assert!(!ep.is_running());

        ep.configure().unwrap();
        assert!(ep.is_running());

        ep.stop().unwrap();
        assert!(!ep.is_running());
    }

    // ── Test: AddressMap ───────────────────────────────────────────────

    #[test]
    fn test_address_map_basics() {
        let mut map = AddressMap::new();
        assert!(map.is_empty());

        map.insert(b"key1", Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(map.len(), 1);

        map.insert(b"key2", Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(map.len(), 2);

        assert_eq!(map.get(b"key1"), Some(&Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(map.get(b"missing"), None);

        let removed = map.remove(b"key1");
        assert_eq!(removed, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
    }

    // ── Test: inbound_packet missing session ───────────────────────────

    #[test]
    fn test_inbound_packet_no_session() {
        let mut ep = TunEndpoint::new(test_net(), "tun0".into());
        ep.configure().unwrap();

        let pkt = make_ipv4_pkt("8.8.8.8", "10.0.0.2");
        let result = ep.handle_inbound_packet(&pkt, b"unknown-session");
        assert!(matches!(result.unwrap_err(), TunError::NoActivePath));
    }

    // ── Test: inbound_packet with valid session ────────────────────────

    #[test]
    fn test_inbound_packet_with_session() {
        let mut ep = TunEndpoint::new(test_net(), "tun0".into());
        ep.configure().unwrap();

        let remote = b"known-session";
        ep.map_session_to_local_ipv4(remote);

        let pkt = make_ipv4_pkt("8.8.8.8", "10.0.0.2");
        let result = ep.handle_inbound_packet(&pkt, remote);
        assert!(result.is_ok());
    }

    // ── Test: IPv4 pool exhaustion ─────────────────────────────────────

    #[test]
    fn test_ipv4_pool_exhaustion() {
        // /30 net: usable=10.0.0.1, 10.0.0.2, broadcast=10.0.0.3
        // Interface IP = 10.0.0.1, only 10.0.0.2 is available.
        let tiny_net = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 30);
        let mut ep = TunEndpoint::new(tiny_net, "tun0".into());

        let ip = ep.map_session_to_local_ipv4(b"first");
        assert!(ip.is_some());
        assert_eq!(ip.unwrap(), Ipv4Addr::new(10, 0, 0, 2));

        let ip = ep.map_session_to_local_ipv4(b"second");
        assert!(ip.is_none());
    }

    // ── Test: traffic_type constants ───────────────────────────────────

    #[test]
    fn test_traffic_type_constants() {
        assert_eq!(traffic_type::UDP, 0);
        assert_eq!(traffic_type::TCP, 1);
        assert_eq!(traffic_type::RAW, 2);
        assert_eq!(traffic_type::TUNNELED_QUIC, 3);
    }

    // ── Test: DNS hook resolves .loki name ─────────────────────────────

    #[test]
    fn test_hook_dns_loki_resolves() {
        use crate::dns::message::{DnsQuestion, QTYPE_A, QCLASS_IN, FLAGS_QR};
        let ep = TunEndpoint::new(test_net(), "tun0".into());



        let mut query = DnsMessage::new(1);
        query.questions.push(DnsQuestion {
            name: "myservice.loki".into(),
            qtype: QTYPE_A,
            qclass: QCLASS_IN,
        });

        let response = ep.hook_dns_query(&query);
        assert!(response.is_some());
        let resp = response.unwrap();
        assert_eq!(resp.id, 1);
        assert!(resp.flags & FLAGS_QR != 0);
        assert_eq!(resp.questions.len(), 1);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].name, "myservice.loki");
        assert_eq!(resp.answers[0].rdata, LOKI_TUN_GATEWAY.to_vec());
    }

    // ── Test: DNS hook ignores non-.loki name ──────────────────────────

    #[test]
    fn test_hook_dns_non_loki_none() {
        use crate::dns::message::{DnsQuestion, QTYPE_A, QCLASS_IN};
        let ep = TunEndpoint::new(test_net(), "tun0".into());

        let mut query = DnsMessage::new(2);
        query.questions.push(DnsQuestion {
            name: "example.com".into(),
            qtype: QTYPE_A,
            qclass: QCLASS_IN,
        });

        let response = ep.hook_dns_query(&query);
        assert!(response.is_none());
    }
}

// TEST MARKER: changes applied
