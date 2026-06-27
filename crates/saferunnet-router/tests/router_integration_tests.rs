use saferunnet_crypto::{KeyAlgorithm, PublicKey};
use saferunnet_link::{FrameKind, LlarpFrame};
use saferunnet_router::{OnionRouter, PathBuilder, RelayHandler};

fn make_key(seed: u8) -> PublicKey {
    PublicKey::from_bytes(KeyAlgorithm::Ed25519, [seed; 32])
}

fn make_nonce(seed: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    n[0] = seed;
    n
}

// ─── Onion Router Integration ───

#[test]
fn onion_router_full_path_roundtrip() {
    let router = OnionRouter::new();
    let hops: Vec<_> = (1..=5).map(make_key).collect();
    let nonce = make_nonce(0xAB);
    let message = b"the quick brown fox jumps over the lazy dog";

    let wrapped = router.wrap(&hops, &nonce, message).unwrap();

    // Simulate each hop peeling
    let mut payload = wrapped;
    for (i, hop) in hops.iter().enumerate() {
        payload = router.unwrap(hop, &nonce, i, &payload).unwrap();
    }
    assert_eq!(payload, message);
}

#[test]
fn onion_router_different_nonce_different_ciphertext() {
    let router = OnionRouter::new();
    let hops: Vec<_> = (0..3).map(make_key).collect();
    let msg = b"same message";

    let c1 = router.wrap(&hops, &make_nonce(1), msg).unwrap();
    let c2 = router.wrap(&hops, &make_nonce(2), msg).unwrap();
    assert_ne!(c1, c2);
}

#[test]
fn onion_router_wrong_key_cannot_decrypt() {
    let router = OnionRouter::new();
    let hops: Vec<_> = (0..3).map(make_key).collect();
    let nonce = make_nonce(42);
    let msg = b"secret";

    let wrapped = router.wrap(&hops, &nonce, msg).unwrap();

    // Try to peel with a key NOT in the path — GCM authentication must fail
    let outsider = make_key(99);
    let result = router.unwrap(&outsider, &nonce, 0, &wrapped);
    assert!(
        result.is_err(),
        "outsider key must be rejected by GCM tag verification"
    );
}

// ─── Path Builder Integration ───

#[test]
fn path_builder_rejects_single_node_with_default_min() {
    let mut builder = PathBuilder::new();
    let nodes = vec![make_key(1)];
    assert!(builder.select_path(&nodes).is_err());
}

#[test]
fn path_builder_accepts_two_nodes_with_default_min() {
    let mut builder = PathBuilder::new().with_min_hops(2);
    let nodes: Vec<_> = (0..2).map(make_key).collect();
    assert!(builder.select_path(&nodes).is_ok());
}

#[test]
fn path_builder_onion_integration() {
    let mut builder = PathBuilder::new();
    let nodes: Vec<_> = (0..4).map(make_key).collect();
    let path = builder.select_path(&nodes).unwrap();
    let nonce = make_nonce(99);

    let wrapped = builder
        .build_onion_payload(&path, &nonce, b"integrated test")
        .unwrap();

    let mut payload = wrapped;
    for (i, hop) in path.hops.iter().enumerate() {
        payload = builder.unwrap_hop(hop, &nonce, i, &payload).unwrap();
    }
    assert_eq!(payload, b"integrated test");
}

// ─── Relay Handler Integration ───

#[test]
fn relay_chain_simulates_multi_hop_forwarding() {
    let handler = RelayHandler::new();
    let router = OnionRouter::new();
    let hops: Vec<_> = (0..3).map(make_key).collect();
    let nonce = make_nonce(77);

    // Build onion payload
    let onion_payload = router.wrap(&hops, &nonce, b"relay chain test").unwrap();

    // Wrap in a relay frame at hop 0
    let frame = LlarpFrame::new(FrameKind::RelayData, 1, 0, onion_payload).unwrap();

    // Hop 0 handles relay
    let result = handler.handle_relay(&frame, &hops[0], &nonce, 3).unwrap();
    let inner_frame = match result {
        saferunnet_router::RelayResult::Forward { next_frame } => next_frame,
        saferunnet_router::RelayResult::Exit { .. } => panic!("unexpected Exit at hop 0"),
    };
    assert_eq!(inner_frame.hop_index, 1);

    // Hop 1 handles relay
    let result = handler
        .handle_relay(&inner_frame, &hops[1], &nonce, 3)
        .unwrap();
    let inner_frame = match result {
        saferunnet_router::RelayResult::Forward { next_frame } => next_frame,
        saferunnet_router::RelayResult::Exit { .. } => panic!("unexpected Exit at hop 1"),
    };
    assert_eq!(inner_frame.hop_index, 2);

    // Hop 2 handles relay (last hop)
    let result = handler
        .handle_relay(&inner_frame, &hops[2], &nonce, 3)
        .unwrap();
    // Last hop may return Exit (decrypted) or Forward
    match result {
        saferunnet_router::RelayResult::Exit { plaintext } => {
            assert_eq!(plaintext, b"relay chain test");
        }
        saferunnet_router::RelayResult::Forward { next_frame } => {
            assert_eq!(next_frame.payload, b"relay chain test");
        }
    }
}

#[test]
fn relay_control_frame_passes_through_all_hops() {
    let handler = RelayHandler::new();
    let frame = LlarpFrame::new(FrameKind::Control, 99, 0, b"control_data".to_vec()).unwrap();

    for hop_key_seed in 1..=3u8 {
        let hop_key = make_key(hop_key_seed);
        let result = handler
            .handle_relay(&frame, &hop_key, &make_nonce(1), 1)
            .unwrap();
        let next = match result {
            saferunnet_router::RelayResult::Forward { next_frame } => next_frame,
            saferunnet_router::RelayResult::Exit { .. } => panic!("unexpected Exit"),
        };
        assert_eq!(next.payload, b"control_data");
    }
}
