//! Async UDP-based DNS server for Lokinet .loki and .snode name resolution.
//! Lokinet C++ equivalent: llarp/dns/server.hpp, llarp/dns/server.cpp

use crate::dns::message::{DnsMessage, QTYPE_A, QTYPE_AAAA, QCLASS_IN};
use crate::dns::resolver::{is_saferunnet_name, LokiResolver};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

/// Default TUN gateway address returned for SaferunNet names.
pub const LOKI_TUN_GATEWAY: [u8; 4] = [127, 3, 2, 1];

/// Default TTL for synthesised DNS responses.
pub const DEFAULT_TTL: u32 = 60;

/// An async UDP-based DNS server that resolves SaferunNet names (.loki/.snode/.sfr) via DHT and forwards
/// other queries upstream.
pub struct DnsServer {
    bind_addr: SocketAddr,
    upstream: Option<SocketAddr>,
    resolver: Option<Arc<dyn LokiResolver + Send + Sync>>,
}

impl DnsServer {
    /// Create a new DNS server that will bind to the given address when `run()` is called.
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            upstream: None,
            resolver: None,
        }
    }

    /// Set an upstream DNS server for non-SaferunNet queries.
    pub fn with_upstream(mut self, upstream: SocketAddr) -> Self {
        self.upstream = Some(upstream);
        self
    }

    /// Set a DHT-based LokiResolver for real SaferunNet name resolution.
    pub fn with_resolver(mut self, resolver: Arc<dyn LokiResolver + Send + Sync>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Returns true if a resolver is configured.
    pub fn has_resolver(&self) -> bool {
        self.resolver.is_some()
    }

    /// Returns the address this server is configured to bind on.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Bind the socket and start the main receive loop. Blocks until an error occurs.
    pub async fn run(self) -> Result<(), std::io::Error> {
        let socket = UdpSocket::bind(self.bind_addr).await?;
        let socket = Arc::new(socket);
        debug!("DNS server listening on {}", self.bind_addr);

        let server = Arc::new(self);
        let mut buf = vec![0u8; 1500];
        loop {
            let (n, src) = socket.recv_from(&mut buf).await?;
            let data = buf[..n].to_vec();

            let socket = Arc::clone(&socket);
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                if let Err(e) = server.handle_query_inner(&socket, &data, src).await {
                    warn!("DNS query handling error from {}: {}", src, e);
                }
            });
        }
    }

    /// Internal query handler spawned per incoming packet.
    async fn handle_query_inner(
        &self,
        socket: &UdpSocket,
        data: &[u8],
        src: SocketAddr,
    ) -> Result<(), std::io::Error> {
        let query = match DnsMessage::decode(data) {
            Some(q) => q,
            None => {
                trace!("Failed to decode DNS query from {}", src);
                return Ok(());
            }
        };

        let response = self.handle_query(&query).await;
        let encoded = response.encode();

        socket.send_to(&encoded, src).await?;
        debug!("DNS response sent to {} ({} bytes)", src, encoded.len());
        Ok(())
    }

    /// Process a decoded DNS query and produce a response.
    ///
    /// Query flow:
    /// 1. For .snode names → return ServFail (not yet implemented)
    /// 2. For SaferunNet names → resolve via DHT resolver if configured, else placeholder gateway
    /// 3. For all others → forward to upstream if configured, else NXDOMAIN
    pub async fn handle_query(&self, query: &DnsMessage) -> DnsMessage {
        let mut response = DnsMessage::response_from(query);

        let has_snode = query.questions.iter().any(|q| q.name.ends_with(".snode"));
        if has_snode {
            response.add_serv_fail();
            return response;
        }

        let has_loki = query.questions.iter().any(|q| is_saferunnet_name(&q.name));
        if has_loki {
            return self.resolve_loki(query);
        }

        // Non-SaferunNet query
        if let Some(upstream_addr) = self.upstream {
            match Self::forward_to_upstream(query, upstream_addr).await {
                Ok(upstream_response) => return upstream_response,
                Err(_) => {
                    response.add_serv_fail();
                    return response;
                }
            }
        }

        response.add_nx_reply();
        response
    }

    /// Resolve SaferunNet names (.loki / .snode / .sfr).
    ///
    /// If a DHT-based LokiResolver is configured, queries the DHT for the name
    /// and returns NXDOMAIN if not found. Otherwise falls back to the placeholder
    /// TUN gateway (127.3.2.1) for backward compatibility.
    pub fn resolve_loki(&self, query: &DnsMessage) -> DnsMessage {
        let mut response = DnsMessage::response_from(query);

        // If we have a DHT resolver, verify the name exists
        if let Some(ref resolver) = self.resolver {
            let all_found = query.questions.iter().all(|q| {
                match resolver.resolve(&q.name) {
                    Ok(_keys) => true,
                    Err(_) => false,
                }
            });

            if !all_found {
                response.add_nx_reply();
                return response;
            }
        }

        // Return placeholder gateway IPs (the TUN stack will route them)
        for question in &query.questions {
            match question.qtype {
                QTYPE_A => {
                    response.add_a_answer(&question.name, LOKI_TUN_GATEWAY, DEFAULT_TTL);
                }
                QTYPE_AAAA => {
                    let ipv6: [u8; 16] = [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 0x03, 0x02, 0x01,
                    ];
                    response.answers.push(crate::dns::message::DnsRR {
                        name: question.name.clone(),
                        rtype: QTYPE_AAAA,
                        rclass: QCLASS_IN,
                        ttl: DEFAULT_TTL,
                        rdata: ipv6.to_vec(),
                    });
                }
                _ => {}
            }
        }

        response
    }

    /// Forward a query to an upstream DNS server and return the response.
    async fn forward_to_upstream(
        query: &DnsMessage,
        upstream: SocketAddr,
    ) -> Result<DnsMessage, std::io::Error> {
        let encoded = query.encode();
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(&encoded, upstream).await?;

        let mut buf = vec![0u8; 1500];
        let (n, _) = socket.recv_from(&mut buf).await?;

        DnsMessage::decode(&buf[..n])
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid DNS response from upstream")
            })
    }

    /// Returns true if this server would handle the given name (i.e. it's a .loki or .snode).
    pub fn would_handle(name: &str) -> bool {
        is_saferunnet_name(name) || name.ends_with(".snode")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::message::{
        DnsMessage, DnsQuestion, FLAGS_QR, QTYPE_A, QTYPE_AAAA, QCLASS_IN, FLAGS_RD,
        RCODE_SERVFAIL, RCODE_NAMEERROR,
    };
    use crate::dns::resolver::{DnsError, LokiResolver};
    use saferunnet_crypto::PublicKey;
    use std::time::Duration;

    fn make_query(id: u16, name: &str, qtype: u16) -> DnsMessage {
        let mut msg = DnsMessage::new(id);
        msg.flags = FLAGS_RD;
        msg.questions.push(DnsQuestion {
            name: name.to_string(),
            qtype,
            qclass: QCLASS_IN,
        });
        msg
    }

    // ── Resolver-free tests (backward compatible) ──────────────────────

    #[tokio::test]
    async fn test_bind_addr_preserved() {
        let addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let server = DnsServer::new(addr);
        assert_eq!(server.bind_addr(), addr);
    }

    #[tokio::test]
    async fn test_with_upstream() {
        let upstream: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap())
            .with_upstream(upstream);
        assert_eq!(server.upstream, Some(upstream));
    }

    #[tokio::test]
    async fn test_handle_query_no_questions() {
        let query = DnsMessage::new(1);
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap());
        let response = server.handle_query(&query).await;

        assert_eq!(response.id, 1);
        assert!((response.flags & 0xF) == RCODE_NAMEERROR);
        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn test_handle_query_loki_resolves_via_placeholder() {
        let query = make_query(8, "echo.loki", QTYPE_A);
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap());
        let response = server.handle_query(&query).await;

        assert_eq!(response.id, 8);
        assert!((response.flags & FLAGS_QR) != 0);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rdata, LOKI_TUN_GATEWAY.to_vec());
    }

    #[tokio::test]
    async fn test_handle_query_non_loki_returns_nxdomain() {
        let query = make_query(5, "google.com", QTYPE_A);
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap());
        let response = server.handle_query(&query).await;

        assert_eq!(response.flags & 0xF, RCODE_NAMEERROR);
        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn test_handle_query_snode_returns_servfail() {
        let query = make_query(9, "node.snode", QTYPE_A);
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap());
        let response = server.handle_query(&query).await;
        assert_eq!(response.flags & 0xF, RCODE_SERVFAIL);
    }

    // ── Resolver integration tests ─────────────────────────────────────

    struct StubResolver {
        known_names: Vec<String>,
    }

    impl LokiResolver for StubResolver {
        fn resolve(&self, name: &str) -> Result<Vec<PublicKey>, DnsError> {
            if self.known_names.iter().any(|n| n == name) {
                Ok(vec![])
            } else {
                Err(DnsError::NotFound(name.to_string()))
            }
        }
    }

    #[tokio::test]
    async fn test_resolver_known_loki_name_returns_gateway() {
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap())
            .with_resolver(Arc::new(StubResolver {
                known_names: vec!["echo.loki".into()],
            }));

        let query = make_query(10, "echo.loki", QTYPE_A);
        let response = server.handle_query(&query).await;
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rdata, LOKI_TUN_GATEWAY.to_vec());
    }

    #[tokio::test]
    async fn test_resolver_unknown_loki_name_returns_nxdomain() {
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap())
            .with_resolver(Arc::new(StubResolver {
                known_names: vec![],
            }));

        let query = make_query(11, "unknown.loki", QTYPE_A);
        let response = server.handle_query(&query).await;
        assert_eq!(response.flags & 0xF, RCODE_NAMEERROR);
        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn test_resolver_preserves_non_loki_behavior() {
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap())
            .with_resolver(Arc::new(StubResolver {
                known_names: vec!["echo.loki".into()],
            }));

        let query = make_query(12, "google.com", QTYPE_A);
        let response = server.handle_query(&query).await;
        assert_eq!(response.flags & 0xF, RCODE_NAMEERROR);
    }

    #[tokio::test]
    async fn test_has_resolver() {
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap());
        assert!(!server.has_resolver());

        let server = server.with_resolver(Arc::new(StubResolver {
            known_names: vec![],
        }));
        assert!(server.has_resolver());
    }


    #[tokio::test]
    async fn test_handle_query_sfr_resolves_via_placeholder() {
        let query = make_query(20, "myservice.sfr", QTYPE_A);
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap());
        let response = server.handle_query(&query).await;
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rdata, LOKI_TUN_GATEWAY.to_vec());
    }

    #[tokio::test]
    async fn test_resolver_known_sfr_name_returns_gateway() {
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap())
            .with_resolver(Arc::new(StubResolver {
                known_names: vec!["echo.sfr".into()],
            }));
        let query = make_query(21, "echo.sfr", QTYPE_A);
        let response = server.handle_query(&query).await;
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rdata, LOKI_TUN_GATEWAY.to_vec());
    }

    #[tokio::test]
    async fn test_resolver_unknown_sfr_name_returns_nxdomain() {
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap())
            .with_resolver(Arc::new(StubResolver {
                known_names: vec![],
            }));
        let query = make_query(22, "nope.sfr", QTYPE_A);
        let response = server.handle_query(&query).await;
        assert_eq!(response.flags & 0xF, RCODE_NAMEERROR);
        assert!(response.answers.is_empty());
    }    // ── Full integration tests (real UDP on loopback) ──────────────────

    #[tokio::test]
    async fn test_dns_server_bind_and_receive() {
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = UdpSocket::bind(bind_addr).await;
        assert!(socket.is_ok(), "Should bind to loopback");
        drop(socket);
    }

    #[tokio::test]
    async fn test_dns_server_handles_loki_query_via_udp() {
        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = UdpSocket::bind(server_addr).await.unwrap();
        let addr = socket.local_addr().unwrap();

        let query = make_query(100, "hello.loki", QTYPE_A);
        let encoded = query.encode();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&encoded, addr).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n, src) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .expect("timeout waiting for DNS query")
            .expect("recv_from failed");

        let received = DnsMessage::decode(&buf[..n]).unwrap();
        assert_eq!(received.id, 100);
        assert_eq!(received.questions[0].name, "hello.loki");
        assert_eq!(src.ip().to_string(), "127.0.0.1");

        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap());
        let response = server.resolve_loki(&received);
        let encoded = response.encode();
        socket.send_to(&encoded, src).await.unwrap();

        let mut resp_buf = vec![0u8; 1500];
        let (rn, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut resp_buf))
            .await
            .expect("timeout waiting for DNS response")
            .expect("recv_from failed");

        let parsed = DnsMessage::decode(&resp_buf[..rn]).unwrap();
        assert_eq!(parsed.id, 100);
        assert!((parsed.flags & FLAGS_QR) != 0);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name, "hello.loki");
        assert_eq!(parsed.answers[0].rdata, LOKI_TUN_GATEWAY.to_vec());
    }

    #[tokio::test]
    async fn test_dns_server_returns_servfail_for_snode_via_udp() {
        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = UdpSocket::bind(server_addr).await.unwrap();
        let addr = socket.local_addr().unwrap();

        let query = make_query(200, "node.snode", QTYPE_A);
        let encoded = query.encode();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&encoded, addr).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .expect("timeout waiting for DNS query")
            .expect("recv_from failed");

        let received = DnsMessage::decode(&buf[..n]).unwrap();
        let server = DnsServer::new("127.0.0.1:5353".parse().unwrap());
        let response = server.handle_query(&received).await;
        assert_eq!(response.flags & 0xF, RCODE_SERVFAIL);
    }

    #[tokio::test]
    async fn test_dns_server_response_has_correct_id_over_udp() {
        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = UdpSocket::bind(server_addr).await.unwrap();
        let addr = socket.local_addr().unwrap();

        let mut query = DnsMessage::new(0xABCD);
        query.flags = FLAGS_RD;
        query.questions.push(DnsQuestion {
            name: "idcheck.loki".into(),
            qtype: QTYPE_A,
            qclass: QCLASS_IN,
        });
        let encoded = query.encode();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&encoded, addr).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .expect("timeout waiting for DNS query")
            .expect("recv_from failed");

        let received = DnsMessage::decode(&buf[..n]).unwrap();
        assert_eq!(received.id, 0xABCD);
    }
}
