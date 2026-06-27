use saferunnet_app::{
    AppKernel, DnsResolverModule, IdentityModule, LinkMessageModule, LinkSessionStateModule,
    PathManagerModule, SessionCoordinatorModule,
};
use saferunnet_crypto::PublicKey;
use saferunnet_dht::NetworkDht;
use saferunnet_dns::resolver::DhtClient;
use saferunnet_identity::NodeIdentity;
use saferunnet_link::{FrameKind, LlarpFrame};
use saferunnet_router::RelayResult;
use saferunnet_transport::{LinkTransport, UdpTransport};
use saferunnetd::forwarder::OnionForwarder;
use std::mem::ManuallyDrop;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

// ─── Unique ID for temp dirs across parallel tests ──────────────────

static NEXT_NODE_ID: AtomicU32 = AtomicU32::new(0);

fn unique_node_name(prefix: &str) -> String {
    let id = NEXT_NODE_ID.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}", prefix, id)
}

// ─── Test harness ───────────────────────────────────────────────────

struct TestNode {
    port: u16,
    dht: Arc<NetworkDht<UdpTransport>>,
    forwarder: Arc<OnionForwarder>,
    public_key: PublicKey,
    transport: Arc<UdpTransport>,
    _kernel: ManuallyDrop<AppKernel>,
}

fn temp_identity_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("saferunnet-test-{}", name));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn addr_of(node: &TestNode) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), node.port)
}

async fn spawn_test_node(name: &str, bootstrap_addrs: Vec<SocketAddr>) -> TestNode {
    let temp_dir = temp_identity_dir(name);
    let keyfile = temp_dir.join("identity.key");

    let identity = IdentityModule::from_runtime_settings(name.to_string(), keyfile);

    let mut kernel = AppKernel::new();
    kernel.register(Box::new(identity));
    kernel.register(Box::new(LinkMessageModule::new()));
    kernel.register(Box::new(LinkSessionStateModule::new()));
    kernel.register(Box::new(PathManagerModule::new()));
    kernel.register(Box::new(DnsResolverModule::new()));
    kernel.register(Box::new(SessionCoordinatorModule::new()));

    kernel.start().expect("kernel start");

    let public_key = kernel
        .services()
        .get::<NodeIdentity>()
        .expect("node identity not registered")
        .public_key
        .clone();

    let transport = Arc::new(
        UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind UDP transport"),
    );
    let port = transport.local_addr().port();

    let dht = Arc::new(NetworkDht::new(
        public_key.clone(),
        transport.clone(),
        bootstrap_addrs,
    ));

    let forwarder = Arc::new(OnionForwarder::new());

    TestNode {
        port,
        dht,
        forwarder,
        public_key,
        transport,
        _kernel: ManuallyDrop::new(kernel),
    }
}

/// Drain any stale datagrams (e.g. DHT bootstrap pings) from the transport buffer.
async fn drain_transport(transport: &UdpTransport) {
    let mut buf = [0u8; 256];
    while let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_millis(50), transport.recv_from(&mut buf)).await
    {}
}

fn make_nonce(seed: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    for (i, byte) in n.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8);
    }
    n
}

// ─── Test 1: 3-node UDP bootstrap and DHT lookup ──────────────────

#[tokio::test]
async fn three_node_udp_bootstrap_and_lookup() {
    let name_a = unique_node_name("dht-a");
    let name_b = unique_node_name("dht-b");
    let name_c = unique_node_name("dht-c");

    let node_a = spawn_test_node(&name_a, vec![]).await;
    let node_b = spawn_test_node(&name_b, vec![addr_of(&node_a)]).await;
    let node_c = spawn_test_node(&name_c, vec![addr_of(&node_a), addr_of(&node_b)]).await;

    // Bootstrap all three via their DHTs
    let (r0, r1, r2) = tokio::join!(
        node_a.dht.bootstrap(),
        node_b.dht.bootstrap(),
        node_c.dht.bootstrap(),
    );
    r0.expect("node A bootstrap");
    r1.expect("node B bootstrap");
    r2.expect("node C bootstrap");

    // Verify calls don''t panic
    let _count_a = node_a.dht.peer_count();
    let _count_b = node_b.dht.peer_count();
    let _count_c = node_c.dht.peer_count();

    // Lookup the intro set for node C''s key from node A
    let intro_results = node_a.dht.lookup_intro_set(&node_c.public_key);
    let _ = intro_results.len();

    // Drain stale bootstrap pings to keep UDP buffers clean for other tests
    drain_transport(&node_a.transport).await;
    drain_transport(&node_b.transport).await;
    drain_transport(&node_c.transport).await;

    drop(node_c);
    drop(node_b);
    drop(node_a);
}

// ─── Test 2: Real onion path relay through 3 nodes ──────────────────

#[tokio::test]
async fn real_onion_path_relay_through_three_nodes() {
    let name_a = unique_node_name("relay-a");
    let name_b = unique_node_name("relay-b");
    let name_c = unique_node_name("relay-c");

    let node_a = spawn_test_node(&name_a, vec![]).await;
    let node_b = spawn_test_node(&name_b, vec![addr_of(&node_a)]).await;
    let node_c = spawn_test_node(&name_c, vec![addr_of(&node_a), addr_of(&node_b)]).await;

    // Bootstrap all into a shared DHT
    let (r0, r1, r2) = tokio::join!(
        node_a.dht.bootstrap(),
        node_b.dht.bootstrap(),
        node_c.dht.bootstrap(),
    );
    r0.expect("bootstrap A");
    r1.expect("bootstrap B");
    r2.expect("bootstrap C");

    // Drain stale DHT bootstrap pings before relay test
    drain_transport(&node_a.transport).await;
    drain_transport(&node_b.transport).await;
    drain_transport(&node_c.transport).await;

    // Build a 2-hop onion path: B → C
    let path = vec![node_b.public_key.clone(), node_c.public_key.clone()];
    let nonce = make_nonce(0xAB);
    let message = b"end-to-end onion relay through real UDP nodes";

    // Wrap the packet using OnionForwarder
    let frame = node_a
        .forwarder
        .wrap_packet(message, &path, &nonce, 1)
        .expect("wrap_packet");
    assert_eq!(frame.kind, FrameKind::RelayData);

    // Send the wrapped frame via UDP from A to B (first hop)
    let encoded = frame.encode();
    node_a
        .transport
        .send_to(&encoded, addr_of(&node_b))
        .await
        .expect("send A->B");

    // B receives and processes the relay frame
    let mut buf = [0u8; 2048];
    let datagram =
        tokio::time::timeout(Duration::from_secs(3), node_b.transport.recv_from(&mut buf))
            .await
            .expect("recv timeout on B")
            .expect("recv on B");
    let frame_b = LlarpFrame::decode(&datagram.data).expect("decode frame on B");
    assert_eq!(frame_b.kind, FrameKind::RelayData);

    // B peels one onion layer via relay_hop
    let result_b = node_b
        .forwarder
        .relay_hop(&frame_b, &node_b.public_key, &nonce, 2)
        .expect("relay_hop B");
    let inner_frame = match result_b {
        RelayResult::Forward { next_frame } => next_frame,
        RelayResult::Exit { .. } => panic!("unexpected Exit at hop B"),
    };
    assert_eq!(inner_frame.hop_index, 1);

    // Send inner frame from B to C
    let encoded2 = inner_frame.encode();
    node_b
        .transport
        .send_to(&encoded2, addr_of(&node_c))
        .await
        .expect("send B->C");

    // C receives
    let datagram2 =
        tokio::time::timeout(Duration::from_secs(3), node_c.transport.recv_from(&mut buf))
            .await
            .expect("recv timeout on C")
            .expect("recv on C");
    let frame_c = LlarpFrame::decode(&datagram2.data).expect("decode frame on C");

    // C peels the final onion layer
    let result_c = node_c
        .forwarder
        .relay_hop(&frame_c, &node_c.public_key, &nonce, 2)
        .expect("relay_hop C");
    let final_frame = match result_c {
        RelayResult::Forward { next_frame } => next_frame,
        RelayResult::Exit { .. } => panic!("unexpected Exit at hop C"),
    };

    // After peeling both layers, the forwarded payload should be the original plaintext
    assert_eq!(final_frame.payload, message);

    drop(node_c);
    drop(node_b);
    drop(node_a);
}

// ─── Test 3: Real UDP control frame exchange ────────────────────────

#[tokio::test]
async fn real_udp_control_frame_exchange() {
    let name_a = unique_node_name("ctrl-a");
    let name_b = unique_node_name("ctrl-b");

    let node_a = spawn_test_node(&name_a, vec![]).await;
    let node_b = spawn_test_node(&name_b, vec![addr_of(&node_a)]).await;

    // Build a Control frame
    let control_payload = b"control-ping-from-A-to-B";
    let frame = LlarpFrame::new(FrameKind::Control, 42, 0, control_payload.to_vec())
        .expect("build control frame");

    // Send from A to B via real UDP
    let encoded = frame.encode();
    node_a
        .transport
        .send_to(&encoded, addr_of(&node_b))
        .await
        .expect("send control frame A->B");

    // B receives and decodes
    let mut buf = [0u8; 2048];
    let datagram =
        tokio::time::timeout(Duration::from_secs(3), node_b.transport.recv_from(&mut buf))
            .await
            .expect("recv timeout on B")
            .expect("recv on B");

    let decoded = LlarpFrame::decode(&datagram.data).expect("decode control frame on B");
    assert_eq!(decoded.kind, FrameKind::Control);
    assert_eq!(decoded.path_id, 42);
    assert_eq!(decoded.hop_index, 0);
    assert_eq!(decoded.payload, control_payload);

    // Also verify it came from A''s address
    assert_eq!(datagram.remote, addr_of(&node_a));

    drop(node_b);
    drop(node_a);
}
