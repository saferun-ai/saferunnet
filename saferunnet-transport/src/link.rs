use crate::traits::*;
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use saferunnet_core::contact::{RouterContact, RouterId};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// Link-layer error type.
#[derive(Debug, Error)]
pub enum LinkError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("timeout connecting to {0}")]
    Timeout(String),
    #[error("no connection to router {0}")]
    NotFound(RouterId),
    #[error("already connected to {0}")]
    AlreadyConnected(RouterId),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("no addresses for router {0}")]
    NoAddresses(RouterId),
}

pub type LinkResult<T> = Result<T, LinkError>;

/// Connection statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectionStats {
    pub service_count: usize,
    pub client_count: usize,
    pub active_count: usize,
}

/// Manages QUIC links to remote SaferunNet routers.
///
/// Lokinet C++ equivalent: `llarp/link/link_manager.hpp` LinkManager
///
/// Maintains two connection pools:
/// - `service_connections`: connections where the remote is a service node
/// - `client_connections`: connections where the remote is a client (service nodes only)
/// Keep-alive interval type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepAliveType {
    Relay,
    Client,
}

impl KeepAliveType {
    pub fn interval_secs(&self) -> u64 { match self { KeepAliveType::Relay => 10, KeepAliveType::Client => 20 } }
    pub fn interval(&self) -> std::time::Duration { std::time::Duration::from_secs(self.interval_secs()) }
    pub fn name(&self) -> &'static str { match self { KeepAliveType::Relay => "relay", KeepAliveType::Client => "client" } }
}

pub struct LinkManager {
    transport: Arc<dyn TransportLayer>,
    service_connections: RwLock<HashMap<RouterId, Box<dyn Connection>>>,
    client_connections: RwLock<HashMap<RouterId, Box<dyn Connection>>>,
    is_service_node: bool,
    persisting_conns: RwLock<HashMap<RouterId, tokio::time::Instant>>,
    keep_alive_count: usize,
}

impl LinkManager {
    /// Create a new LinkManager.
    pub fn new(transport: Arc<dyn TransportLayer>, is_service_node: bool) -> Self {
        Self {
            transport,
            service_connections: RwLock::new(HashMap::new()),
            client_connections: RwLock::new(HashMap::new()),
            is_service_node,
            persisting_conns: RwLock::new(HashMap::new()),
            keep_alive_count: 4,
        }
    }

    /// Set the number of keep-alive connections to maintain.
    pub fn set_keep_alive_count(&mut self, count: usize) {
        self.keep_alive_count = count;
    }
    pub fn keep_alive_type(&self) -> KeepAliveType {
        if self.is_service_node { KeepAliveType::Relay } else { KeepAliveType::Client }
    }


    /// Connect to a remote router using its RouterContact.
    pub async fn connect_to(&self, rc: &RouterContact) -> LinkResult<()> {
        let rid = RouterId::from_contact(rc);
        let addr = rc
            .addresses
            .first()
            .ok_or_else(|| LinkError::NoAddresses(rid))?
            .to_owned();

        // Check if already connected
        if self.have_connection_to(&rid) {
            return Err(LinkError::AlreadyConnected(rid));
        }

        let conn = self
            .transport
            .connect(addr)
            .await
            .map_err(|e| LinkError::ConnectionFailed(e.to_string()))?;

        self.service_connections.write().insert(rid, conn);
        Ok(())
    }

    /// Close connection to a router.
    pub fn close_connection(&self, rid: RouterId) {
        if let Some(conn) = self.service_connections.write().remove(&rid) {
            tokio::spawn(async move {
                conn.close(0).await;
            });
        }
        self.client_connections.write().remove(&rid);
        self.persisting_conns.write().remove(&rid);
    }

    /// Check if we have any connection to this router.
    pub fn have_connection_to(&self, rid: &RouterId) -> bool {
        self.have_service_connection_to(rid) || self.have_client_connection_to(rid)
    }

    /// Check if we have a service-node connection.
    pub fn have_service_connection_to(&self, rid: &RouterId) -> bool {
        self.service_connections.read().contains_key(rid)
    }

    /// Check if we have a client connection (only relevant for service nodes).
    pub fn have_client_connection_to(&self, rid: &RouterId) -> bool {
        self.client_connections.read().contains_key(rid)
    }

    /// Send a datagram message to a router.
    pub async fn send_data_message(
        &self,
        rid: &RouterId,
        data: Bytes,
    ) -> LinkResult<()> {
        let guard = self.service_connections.read();
        let conn = guard
            .get(rid)
            .ok_or_else(|| LinkError::NotFound(*rid))?;
        conn.send_datagram(data)
            .await
            .map_err(LinkError::Transport)
    }

    /// Send a control message and await response.
    pub async fn send_control_message(
        &self,
        rid: &RouterId,
        data: Bytes,
    ) -> LinkResult<Bytes> {
        let guard = self.service_connections.read();
        let conn = guard
            .get(rid)
            .ok_or_else(|| LinkError::NotFound(*rid))?;
        let mut stream = conn.open_stream().await.map_err(LinkError::Transport)?;
        stream.send(data).await.map_err(LinkError::Transport)?;
        stream.finish().await.map_err(LinkError::Transport)?;
        stream
            .recv()
            .await
            .map_err(LinkError::Transport)?
            .ok_or_else(|| LinkError::NotFound(*rid))
    }

    /// Iterate over all connections.
    pub fn for_each_connection<F>(&self, mut f: F)
    where
        F: FnMut(&RouterId, &dyn Connection),
    {
        for (rid, conn) in self.service_connections.read().iter() {
            f(rid, conn.as_ref());
        }
        if self.is_service_node {
            for (rid, conn) in self.client_connections.read().iter() {
                f(rid, conn.as_ref());
            }
        }
    }

    /// Get connection statistics.
    pub fn connection_stats(&self) -> ConnectionStats {
        let service = self.service_connections.read();
        let client = self.client_connections.read();
        ConnectionStats {
            service_count: service.len(),
            client_count: client.len(),
            active_count: service.len() + client.len(),
        }
    }

    /// Whether this node is a service node.
    pub fn is_service_node(&self) -> bool {
        self.is_service_node
    }

    // ── Keep-alive ──────────────────────────────────────────────

    /// Attempt to connect to more routers to maintain minimum connections (stub).
    pub fn connect_to_keep_alive(&self, _num_conns: usize) {
        // Full implementation requires NodeDB access for random router selection.
        // Stub: no-op until NodeDB is implemented.
    }

    /// Persist a connection until the given deadline.
    pub fn set_conn_persist(&self, rid: RouterId, duration: Duration) {
        self.persisting_conns
            .write()
            .insert(rid, tokio::time::Instant::now() + duration);
    }

    /// Check and close expired persisted connections.
    pub fn check_persisting_conns(&self) {
        let now = tokio::time::Instant::now();
        let expired: Vec<RouterId> = self
            .persisting_conns
            .read()
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(rid, _)| *rid)
            .collect();
        for rid in expired {
            self.persisting_conns.write().remove(&rid);
            // Don't close — just stop persisting
        }
    }

    // ── Gossip stubs (delegated to router layer) ────────────────

    /// Gossip our RouterContact to connected peers (stub).
    pub fn gossip_rc(&self) {
        // Full implementation in router layer
    }

    /// Handle an incoming gossip message (stub).
    pub fn handle_gossip_rc(&self, _data: &[u8]) {
        // Full implementation in router layer
    }

    // ── Path message stubs ──────────────────────────────────────

    /// Handle incoming path data message (stub).
    pub fn handle_path_data_message(&self, _data: &[u8]) {
        // Forwarded to path module
    }

    /// Handle incoming path control message (stub).
    pub fn handle_path_control(&self, _data: &[u8]) {
        // Forwarded to path module
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex as StdMutex;

    // ── Mock transport for testing ──────────────────────────────

    struct MockConnection {
        addr: SocketAddr,
        closed: AtomicBool,
        datagrams: StdMutex<Vec<Bytes>>,
    }

    impl MockConnection {
        fn new(addr: SocketAddr) -> Self {
            Self {
                addr,
                closed: AtomicBool::new(false),
                datagrams: StdMutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl Connection for MockConnection {
        async fn send_datagram(&self, data: Bytes) -> TransportResult<()> {
            self.datagrams.lock().unwrap().push(data);
            Ok(())
        }
        async fn recv_datagram(&self) -> TransportResult<Bytes> {
            Err(TransportError::RecvFailed("mock".into()))
        }
        async fn open_stream(&self) -> TransportResult<Box<dyn ControlStream>> {
            Ok(Box::new(MockControlStream::default()))
        }
        async fn accept_stream(&self) -> TransportResult<Box<dyn ControlStream>> {
            Err(TransportError::Closed)
        }
        async fn close(&self, _code: u64) {
            self.closed.store(true, Ordering::SeqCst);
        }
        fn remote_addr(&self) -> SocketAddr {
            self.addr
        }
        fn is_inbound(&self) -> bool {
            false
        }
        fn clone_connection(&self) -> Box<dyn Connection> {
            Box::new(Self {
                addr: self.addr,
                closed: AtomicBool::new(self.closed.load(Ordering::SeqCst)),
                datagrams: StdMutex::new(self.datagrams.lock().unwrap().clone()),
            })
        }
    }

    #[derive(Default)]
    struct MockControlStream {
        sent: StdMutex<Vec<Bytes>>,
        response: StdMutex<Option<Bytes>>,
    }

    #[async_trait]
    impl ControlStream for MockControlStream {
        async fn send(&mut self, data: Bytes) -> TransportResult<()> {
            self.sent.lock().unwrap().push(data.clone());
            // Echo back as response
            *self.response.lock().unwrap() = Some(data);
            Ok(())
        }
        async fn recv(&mut self) -> TransportResult<Option<Bytes>> {
            Ok(self.response.lock().unwrap().clone())
        }
        async fn finish(&mut self) -> TransportResult<()> {
            Ok(())
        }
    }

    struct MockTransport {
        connections: StdMutex<HashMap<SocketAddr, Box<dyn Connection>>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                connections: StdMutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl TransportLayer for MockTransport {
        async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn Connection>> {
            let conn: Box<dyn Connection> = Box::new(MockConnection::new(addr));
            self.connections.lock().unwrap().insert(addr, conn.clone_connection());
            Ok(conn)
        }
        async fn listen(&self, _addr: SocketAddr) -> TransportResult<Box<dyn Listener>> {
            Err(TransportError::BindFailed("mock".into()))
        }
    }

    fn make_test_rc(addr_str: &str) -> RouterContact {
        let mut rc = RouterContact::new(vec![0u8; 32]);
        rc.addresses.push(addr_str.parse().unwrap());
        rc
    }

    fn make_test_rc_with_key(addr_str: &str, key_byte: u8) -> RouterContact {
        let mut rc = RouterContact::new(vec![key_byte; 32]);
        rc.addresses.push(addr_str.parse().unwrap());
        rc
    }

    // ── Tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_new_link_manager() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        assert!(!lm.is_service_node());
        let stats = lm.connection_stats();
        assert_eq!(stats.service_count, 0);
        assert_eq!(stats.client_count, 0);
        assert_eq!(stats.active_count, 0);
    }

    #[tokio::test]
    async fn test_service_node_flag() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, true);
        assert!(lm.is_service_node());
    }

    #[tokio::test]
    async fn test_connect_to_peer() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        let rc = make_test_rc("10.0.0.1:1090");
        let rid = RouterId::from_contact(&rc);

        lm.connect_to(&rc).await.unwrap();
        assert!(lm.have_connection_to(&rid));
        assert!(lm.have_service_connection_to(&rid));
        assert_eq!(lm.connection_stats().service_count, 1);
    }

    #[tokio::test]
    async fn test_duplicate_connect() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        let rc = make_test_rc("10.0.0.1:1090");

        lm.connect_to(&rc).await.unwrap();
        let result = lm.connect_to(&rc).await;
        assert!(matches!(result, Err(LinkError::AlreadyConnected(_))));
    }

    #[tokio::test]
    async fn test_close_connection() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        let rc = make_test_rc("10.0.0.1:1090");
        let rid = RouterId::from_contact(&rc);

        lm.connect_to(&rc).await.unwrap();
        assert!(lm.have_connection_to(&rid));

        lm.close_connection(rid);
        // Give the spawned task time to run
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!lm.have_service_connection_to(&rid));
    }

    #[tokio::test]
    async fn test_have_connection_to_false_for_unknown() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        let rid = RouterId([0xAAu8; 32]);
        assert!(!lm.have_connection_to(&rid));
    }

    #[tokio::test]
    async fn test_send_data_message_error_on_unknown() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        let rid = RouterId([0xBBu8; 32]);
        let result = lm.send_data_message(&rid, Bytes::from("hello")).await;
        assert!(matches!(result, Err(LinkError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_send_control_message_error_on_unknown() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        let rid = RouterId([0xCCu8; 32]);
        let result = lm.send_control_message(&rid, Bytes::from("ping")).await;
        assert!(matches!(result, Err(LinkError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_for_each_connection_iterates() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        let rc = make_test_rc("10.0.0.1:1090");
        lm.connect_to(&rc).await.unwrap();

        let mut count = 0;
        lm.for_each_connection(|_rid, _conn| {
            count += 1;
        });
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_connection_stats_after_multiple_connects() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);

        let rc1 = make_test_rc_with_key("10.0.0.1:1090", 1);
        let rc2 = make_test_rc_with_key("10.0.0.2:1090", 2);

        lm.connect_to(&rc1).await.unwrap();
        lm.connect_to(&rc2).await.unwrap();

        let stats = lm.connection_stats();
        assert_eq!(stats.service_count, 2);
        assert_eq!(stats.active_count, 2);
    }

    #[tokio::test]
    async fn test_no_addresses_error() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        let rc = RouterContact::new(vec![0u8; 32]); // no addresses
        let _rid = RouterId::from_contact(&rc);
        let result = lm.connect_to(&rc).await;
        assert!(matches!(result, Err(LinkError::NoAddresses(_))));
    }

    #[tokio::test]
    async fn test_set_conn_persist_and_check() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        let rc = make_test_rc("10.0.0.1:1090");
        let rid = RouterId::from_contact(&rc);

        lm.connect_to(&rc).await.unwrap();
        // Persist for 1 second
        lm.set_conn_persist(rid, Duration::from_secs(1));

        // Immediately check — should still be persisting
        lm.check_persisting_conns();
        assert!(lm.have_connection_to(&rid));

        // Wait for persistence to expire
        tokio::time::sleep(Duration::from_secs(2)).await;
        lm.check_persisting_conns();
        // Connection should still exist (we only stop persisting, don't close)
        assert!(lm.have_connection_to(&rid));
    }

    #[tokio::test]
    async fn test_send_data_message_roundtrip() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        let rc = make_test_rc("10.0.0.1:1090");
        let rid = RouterId::from_contact(&rc);

        lm.connect_to(&rc).await.unwrap();
        let result = lm.send_data_message(&rid, Bytes::from("test_payload")).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_control_message_roundtrip() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        let rc = make_test_rc("10.0.0.1:1090");
        let rid = RouterId::from_contact(&rc);

        lm.connect_to(&rc).await.unwrap();
        let result = lm
            .send_control_message(&rid, Bytes::from("echo"))
            .await
            .unwrap();
        assert_eq!(result, Bytes::from("echo"));
    }

    #[test]
    fn test_keep_alive_type_relay() {
        let kt = KeepAliveType::Relay;
        assert_eq!(kt.interval_secs(), 10);
        assert_eq!(kt.name(), "relay");
        assert_eq!(kt.interval(), Duration::from_secs(10));
    }

    #[test]
    fn test_keep_alive_type_client() {
        let kt = KeepAliveType::Client;
        assert_eq!(kt.interval_secs(), 20);
        assert_eq!(kt.name(), "client");
        assert_eq!(kt.interval(), Duration::from_secs(20));
    }

    #[test]
    fn test_keep_alive_type_service_node() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, true);
        assert_eq!(lm.keep_alive_type(), KeepAliveType::Relay);
    }

    #[test]
    fn test_keep_alive_type_client_node() {
        let transport = Arc::new(MockTransport::new());
        let lm = LinkManager::new(transport, false);
        assert_eq!(lm.keep_alive_type(), KeepAliveType::Client);
    }
}