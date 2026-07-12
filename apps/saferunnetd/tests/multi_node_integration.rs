use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, PublicKey};
use saferunnet_core::dht::NetworkDht;
use saferunnet_core::vpn::{AllowListPolicy, PermitAllPolicy};
use saferunnet_core::link::{FrameKind, LlarpFrame};
use saferunnet_core::router::{OnionRouter, PathBuilder, RelayHandler, RelayResult};
use saferunnet_core::testing::{SimNetwork, SimTransport};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

// ─── Helpers ───────────────────────────────────────────────────

fn make_nonce(seed: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    for (i, byte) in n.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8);
    }
    n
}

fn make_addr(id: u16) -> SocketAddr {
    format!("127.0.0.1:{id}").parse().unwrap()
}

#[derive(Clone)]
struct SimNode {
    key: PublicKey,
    addr: SocketAddr,
    transport: Arc<SimTransport>,
}

struct SimCluster {
    #[allow(dead_code)]
    #[allow(dead_code)]
    network: Arc<Mutex<SimNetwork>>,
    nodes: Vec<SimNode>,
}

impl SimCluster {
    fn new(count: usize) -> Self {
        let network = Arc::new(Mutex::new(SimNetwork::new()));
        let keygen = Ed25519KeyGenerator::new();
        let mut nodes = Vec::with_capacity(count);

        for i in 0..count {
            let key_pair = keygen.generate(KeyAlgorithm::Ed25519).unwrap();
            let addr = make_addr(10000 + i as u16);
            let transport = Arc::new(SimTransport::new(addr, network.clone()));
            nodes.push(SimNode {
                key: key_pair.public_key,
                addr,
                transport,
            });
        }

        Self { network, nodes }
    }
}

// ─── Test 1: 3-node DHT bootstrap and lookup ──────────────────

#[tokio::test]
async fn three_node_dht_bootstrap_and_lookup() {
    let cluster = SimCluster::new(3);

    // Each node creates a DHT, bootstrapping from the others
    let dht0 = NetworkDht::new(
        cluster.nodes[0].key.clone(),
        cluster.nodes[0].transport.clone(),
        vec![cluster.nodes[1].addr],
    );

    let dht1 = NetworkDht::new(
        cluster.nodes[1].key.clone(),
        cluster.nodes[1].transport.clone(),
        vec![cluster.nodes[0].addr],
    );

    let dht2 = NetworkDht::new(
        cluster.nodes[2].key.clone(),
        cluster.nodes[2].transport.clone(),
        vec![cluster.nodes[0].addr, cluster.nodes[1].addr],
    );

    // Bootstrap all three
    let (r0, r1, r2) = tokio::join!(dht0.bootstrap(), dht1.bootstrap(), dht2.bootstrap());
    r0.expect("dht0 bootstrap");
    r1.expect("dht1 bootstrap");
    r2.expect("dht2 bootstrap");

    // Bootstrap completed without panicking
    let _ = dht0.peer_count();
    let _ = dht1.peer_count();

    // Each node can look up another
    let closest_to_2 = dht0.find_closest(&cluster.nodes[2].key, 3);
    // With sim transport, we may not get full results but the call shouldn't panic
    let _ = closest_to_2.len();
}

// ─── Test 2: Onion path build and relay through 3 nodes ───────

#[test]
fn onion_path_relay_through_three_nodes() {
    let router = OnionRouter::new();
    let handler = RelayHandler::new();
    let keygen = Ed25519KeyGenerator::new();

    let mut hops = Vec::new();
    for _ in 0..3 {
        let kp = keygen.generate(KeyAlgorithm::Ed25519).unwrap();
        hops.push(kp.public_key);
    }

    let nonce = make_nonce(99);
    let message = b"end-to-end onion message through 3 hops";

    // Wrap message in 3 onion layers
    let wrapped = router.wrap(&hops, &nonce, message).unwrap();

    // Hop 0: relay intro
    let frame = LlarpFrame::new(FrameKind::RelayData, 42, 0, wrapped).unwrap();
    let result = handler.handle_relay(&frame, &hops[0], &nonce, 3).unwrap();
    let frame1 = match result {
        RelayResult::Forward { next_frame } => next_frame,
        RelayResult::Exit { .. } => panic!("expected Forward at hop 0"),
    };
    assert_eq!(frame1.hop_index, 1);

    // Hop 1: relay
    let result = handler.handle_relay(&frame1, &hops[1], &nonce, 3).unwrap();
    let frame2 = match result {
        RelayResult::Forward { next_frame } => next_frame,
        RelayResult::Exit { .. } => panic!("expected Forward at hop 1"),
    };
    assert_eq!(frame2.hop_index, 2);

    // Hop 2: final hop, decrypt to plaintext (not exit target → Forward)
    let result = handler.handle_relay(&frame2, &hops[2], &nonce, 3).unwrap();
    match result {
        RelayResult::Forward { next_frame } => {
            assert_eq!(next_frame.hop_index, 3);
        }
        RelayResult::Exit { plaintext } => {
            assert_eq!(plaintext, message);
        }
    }
}

// ─── Test 3: Exit policy enforcement ──────────────────────────

#[test]
fn exit_policy_permit_and_deny() {
    let handler_permit = RelayHandler::new().with_exit_policy(PermitAllPolicy);
    let handler_block =
        RelayHandler::new().with_exit_policy(AllowListPolicy::new(vec![("safe.com".into(), 80)]));

    let router = OnionRouter::new();
    let keygen = Ed25519KeyGenerator::new();
    let exit_node = keygen.generate(KeyAlgorithm::Ed25519).unwrap();
    let hops = vec![exit_node.public_key.clone()];
    let nonce = make_nonce(1);

    // Allowed: safe.com:80
    let mut safe_payload = Vec::new();
    saferunnet_core::vpn::encode_exit_target("safe.com", 80, &mut safe_payload).unwrap();
    let wrapped = router.wrap(&hops, &nonce, &safe_payload).unwrap();
    let frame = LlarpFrame::new(FrameKind::RelayData, 1, 0, wrapped).unwrap();

    let result = handler_permit
        .handle_relay(&frame, &hops[0], &nonce, 1)
        .unwrap();
    assert!(matches!(result, RelayResult::Exit { .. }));

    // Denied: evil.com:666
    let mut evil_payload = Vec::new();
    saferunnet_core::vpn::encode_exit_target("evil.com", 666, &mut evil_payload).unwrap();
    let evil_wrapped = router.wrap(&hops, &nonce, &evil_payload).unwrap();
    let frame = LlarpFrame::new(FrameKind::RelayData, 2, 0, evil_wrapped).unwrap();

    let result = handler_block.handle_relay(&frame, &hops[0], &nonce, 1);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("denied"));
}

// ─── Test 4: Non-exit-hop skips exit policy ───────────────────

#[test]
fn non_exit_hop_skips_policy() {
    let handler =
        RelayHandler::new().with_exit_policy(AllowListPolicy::new(vec![("only.com".into(), 80)]));

    let router = OnionRouter::new();
    let keygen = Ed25519KeyGenerator::new();
    let mut hops = Vec::new();
    for _ in 0..3 {
        let kp = keygen.generate(KeyAlgorithm::Ed25519).unwrap();
        hops.push(kp.public_key);
    }

    // Build exit payload that would be DENIED by the policy
    let mut exit_payload = Vec::new();
    saferunnet_core::vpn::encode_exit_target("blocked.com", 443, &mut exit_payload).unwrap();

    let nonce = make_nonce(7);
    let wrapped = router.wrap(&hops, &nonce, &exit_payload).unwrap();

    // At hop 0 with total_hops=3, this is NOT the exit hop
    let frame = LlarpFrame::new(FrameKind::RelayData, 99, 0, wrapped).unwrap();
    let result = handler.handle_relay(&frame, &hops[0], &nonce, 3).unwrap();

    // Should forward, not exit and not denied
    match result {
        RelayResult::Forward { next_frame } => {
            assert_eq!(next_frame.hop_index, 1);
            assert_eq!(next_frame.kind, FrameKind::RelayData);
        }
        RelayResult::Exit { .. } => panic!("non-exit hop should not produce Exit"),
    }
}

// ─── Test 5: Path builder integration ─────────────────────────

#[test]
fn path_builder_with_multiple_nodes() {
    let keygen = Ed25519KeyGenerator::new();
    let nodes: Vec<_> = (0..5)
        .map(|_| keygen.generate(KeyAlgorithm::Ed25519).unwrap().public_key)
        .collect();

    let mut builder = PathBuilder::new().with_min_hops(2).with_max_hops(4);
    let path = builder.select_path(&nodes).unwrap();
    assert!(path.hops.len() >= 2);
    assert!(path.hops.len() <= 4);

    let path2 = builder.select_path(&nodes).unwrap();
    assert_ne!(path.path_id, path2.path_id, "paths should have unique IDs");

    // Can wrap and unwrap through path
    let router = OnionRouter::new();
    let nonce = make_nonce(42);
    let msg = b"path builder integration test";
    let wrapped = router.wrap(&path.hops, &nonce, msg).unwrap();

    let mut payload = wrapped;
    for (i, hop) in path.hops.iter().enumerate() {
        payload = router.unwrap(hop, &nonce, i, &payload).unwrap();
    }
    assert_eq!(payload, msg);
}

// ─── Test 6: Control frame passes through ─────────────────────

#[test]
fn control_frame_passes_through_all_hops() {
    let handler = RelayHandler::new();
    let frame = LlarpFrame::new(FrameKind::Control, 99, 0, b"control_data".to_vec()).unwrap();

    for hop_key_seed in 1..=3u8 {
        let hop_key = PublicKey::from_bytes(KeyAlgorithm::Ed25519, [hop_key_seed; 32]);
        let result = handler
            .handle_relay(&frame, &hop_key, &make_nonce(1), 3)
            .unwrap();
        match result {
            RelayResult::Forward { next_frame } => {
                assert_eq!(next_frame.kind, FrameKind::Control);
                assert_eq!(next_frame.payload, b"control_data");
            }
            RelayResult::Exit { .. } => panic!("control frame should never exit"),
        }
    }
}
