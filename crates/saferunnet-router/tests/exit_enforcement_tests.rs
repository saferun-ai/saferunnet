use saferunnet_crypto::{KeyAlgorithm, PublicKey};
use saferunnet_exit::{AllowListPolicy, PermitAllPolicy};
use saferunnet_link::{FrameKind, LlarpFrame};
use saferunnet_router::{OnionRouter, RelayHandler, RelayResult};

fn make_key(seed: u8) -> PublicKey {
    PublicKey::from_bytes(KeyAlgorithm::Ed25519, [seed; 32])
}

fn make_nonce(seed: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    for (i, byte) in n.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8);
    }
    n
}

/// Build an exit-target payload: addr_len + addr + port
fn exit_payload(addr: &str, port: u16) -> Vec<u8> {
    let mut p = Vec::new();
    saferunnet_exit::encode_exit_target(addr, port, &mut p).unwrap();
    p
}

// ─── PermitAll ───

#[test]
fn exit_with_permit_all_allows_traffic() {
    let handler = RelayHandler::new().with_exit_policy(PermitAllPolicy);
    let onion = OnionRouter::new();
    let hops = vec![make_key(1)];
    let nonce = make_nonce(42);

    let target = exit_payload("example.com", 443);
    let wrapped = onion.wrap(&hops, &nonce, &target).unwrap();
    let frame = LlarpFrame::new(FrameKind::RelayData, 1, 0, wrapped).unwrap();

    let result = handler.handle_relay(&frame, &hops[0], &nonce, 1).unwrap();
    match result {
        RelayResult::Exit { plaintext } => {
            assert_eq!(plaintext, target);
        }
        RelayResult::Forward { .. } => panic!("expected Exit, got Forward"),
    }
}

// ─── AllowList: allowed ───

#[test]
fn exit_with_allowlist_allows_listed_target() {
    let handler = RelayHandler::new()
        .with_exit_policy(AllowListPolicy::new(vec![("example.com".into(), 443)]));
    let onion = OnionRouter::new();
    let hops = vec![make_key(1)];
    let nonce = make_nonce(1);

    let target = exit_payload("example.com", 443);
    let wrapped = onion.wrap(&hops, &nonce, &target).unwrap();
    let frame = LlarpFrame::new(FrameKind::RelayData, 2, 0, wrapped).unwrap();

    let result = handler.handle_relay(&frame, &hops[0], &nonce, 1).unwrap();
    assert!(matches!(result, RelayResult::Exit { .. }));
}

// ─── AllowList: denied ───

#[test]
fn exit_with_allowlist_denies_unlisted_target() {
    let handler =
        RelayHandler::new().with_exit_policy(AllowListPolicy::new(vec![("safe.com".into(), 80)]));
    let onion = OnionRouter::new();
    let hops = vec![make_key(1)];
    let nonce = make_nonce(2);

    let target = exit_payload("evil.com", 666);
    let wrapped = onion.wrap(&hops, &nonce, &target).unwrap();
    let frame = LlarpFrame::new(FrameKind::RelayData, 3, 0, wrapped).unwrap();

    let result = handler.handle_relay(&frame, &hops[0], &nonce, 1);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("denied"));
}

// ─── No policy: forwards ───

#[test]
fn exit_without_policy_parses_exit_target() {
    let handler = RelayHandler::new(); // no exit policy
    let onion = OnionRouter::new();
    let hops = vec![make_key(1)];
    let nonce = make_nonce(3);

    let target = exit_payload("any.com", 8080);
    let wrapped = onion.wrap(&hops, &nonce, &target).unwrap();
    let frame = LlarpFrame::new(FrameKind::RelayData, 4, 0, wrapped).unwrap();

    let result = handler.handle_relay(&frame, &hops[0], &nonce, 1).unwrap();
    // No exit policy → still returns Exit since we parsed target
    assert!(matches!(result, RelayResult::Exit { .. }));
}

// ─── Non-exit payload: forwards ───

#[test]
fn non_exit_payload_forwards_normally() {
    let handler = RelayHandler::new().with_exit_policy(PermitAllPolicy);
    let onion = OnionRouter::new();
    let hops = vec![make_key(1), make_key(2)];
    let nonce = make_nonce(4);

    // Payload that does NOT parse as exit target (not len-prefixed)
    let plaintext = b"regular transit data not an exit target";
    let wrapped = onion.wrap(&hops, &nonce, plaintext).unwrap();
    let frame = LlarpFrame::new(FrameKind::RelayData, 5, 0, wrapped).unwrap();

    let result = handler.handle_relay(&frame, &hops[0], &nonce, 1).unwrap();
    // Should forward since payload doesn't parse as exit target
    assert!(matches!(result, RelayResult::Forward { .. }));
}
