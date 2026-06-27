//! Performance benchmarks for onion routing operations.
//!
//! Run with: cargo test -p saferunnet-router --test benchmarks -- --nocapture

use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, PublicKey};
use saferunnet_dht::routing::{RouterEntry, RoutingTable};
use saferunnet_link::{FrameKind, LlarpFrame};
use saferunnet_router::{OnionRouter, RelayHandler};
use std::time::Instant;

fn make_nonce(seed: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    for (i, byte) in n.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8);
    }
    n
}

fn make_keys(count: usize) -> Vec<PublicKey> {
    let keygen = Ed25519KeyGenerator::new();
    (0..count)
        .map(|_| keygen.generate(KeyAlgorithm::Ed25519).unwrap().public_key)
        .collect()
}

// ─── Onion wrap/unwrap throughput ──────────────────────────────

#[test]
fn bench_onion_wrap_unwrap() {
    let router = OnionRouter::new();
    let hops = make_keys(5);
    let nonce = make_nonce(0xAB);
    let message = vec![0x42u8; 1024]; // 1 KB payload

    const ITERATIONS: u32 = 1000;

    // Warmup
    for _ in 0..100 {
        let wrapped = router.wrap(&hops, &nonce, &message).unwrap();
        let mut payload = wrapped;
        for (i, hop) in hops.iter().enumerate() {
            payload = router.unwrap(hop, &nonce, i, &payload).unwrap();
        }
    }

    // Benchmark wrap + full unwrap
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let wrapped = router.wrap(&hops, &nonce, &message).unwrap();
        let mut payload = wrapped;
        for (i, hop) in hops.iter().enumerate() {
            payload = router.unwrap(hop, &nonce, i, &payload).unwrap();
        }
    }
    let elapsed = start.elapsed();

    let total_hops = ITERATIONS * (hops.len() as u32 * 2); // wrap + unwrap per hop
    let ops_per_sec = total_hops as f64 / elapsed.as_secs_f64();

    println!("Onion wrap/unwrap: {ITERATIONS} iterations, 5 hops, 1 KB payload");
    println!("  Total time: {elapsed:.2?}");
    println!("  Hop ops/sec: {ops_per_sec:.0}");
    println!(
        "  Throughput: ~{:.1} MB/s",
        (ITERATIONS as f64 * message.len() as f64) / elapsed.as_secs_f64() / 1_000_000.0
    );

    // Must complete in reasonable time (< 5 sec for 1000 iterations)
    assert!(elapsed.as_secs() < 5, "onion ops too slow");
}

// ─── Relay chain throughput ───────────────────────────────────

#[test]
fn bench_relay_chain() {
    let handler = RelayHandler::new();
    let router = OnionRouter::new();
    let hops = make_keys(3);
    let nonce = make_nonce(77);
    let message = vec![0xAAu8; 512]; // 512 B payload

    const ITERATIONS: u32 = 500;

    // Warmup
    for _ in 0..50 {
        let wrapped = router.wrap(&hops, &nonce, &message).unwrap();
        let frame = LlarpFrame::new(FrameKind::RelayData, 1, 0, wrapped).unwrap();
        let mut current = frame;
        for hop in hops.iter() {
            let result = handler.handle_relay(&current, hop, &nonce, 3).unwrap();
            match result {
                saferunnet_router::RelayResult::Forward { next_frame } => current = next_frame,
                saferunnet_router::RelayResult::Exit { .. } => break,
            }
        }
    }

    // Benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let wrapped = router.wrap(&hops, &nonce, &message).unwrap();
        let frame = LlarpFrame::new(FrameKind::RelayData, 1, 0, wrapped).unwrap();
        let mut current = frame;
        for hop in hops.iter() {
            let result = handler.handle_relay(&current, hop, &nonce, 3).unwrap();
            match result {
                saferunnet_router::RelayResult::Forward { next_frame } => current = next_frame,
                saferunnet_router::RelayResult::Exit { .. } => break,
            }
        }
    }
    let elapsed = start.elapsed();

    let ops_per_sec = ITERATIONS as f64 / elapsed.as_secs_f64();

    println!("Relay chain: {ITERATIONS} iterations, 3 hops, 512 B payload");
    println!("  Total time: {elapsed:.2?}");
    println!("  Chains/sec: {ops_per_sec:.0}");

    // Must complete in reasonable time
    assert!(elapsed.as_secs() < 5, "relay chain too slow");
}

// ─── DHT routing table operations ─────────────────────────────

#[test]
fn bench_routing_table_operations() {
    let local_key = make_keys(1).pop().unwrap();
    let mut table = RoutingTable::new(local_key);
    let peers = make_keys(200);

    // Populate
    let start = Instant::now();
    for peer in &peers {
        let distance = RoutingTable::xor_distance(table.local_key(), peer);
        let entry = RouterEntry {
            public_key: peer.clone(),
            distance,
            last_seen: 1000,
        };
        let _ = table.add(entry);
    }
    let populate_time = start.elapsed();
    println!("Routing table populate 200 nodes: {populate_time:.2?}");

    // Lookup
    let target = peers[100].clone();
    let start = Instant::now();
    const LOOKUP_ITERS: u32 = 10_000;
    for _ in 0..LOOKUP_ITERS {
        let _ = table.find_closest(&target, 3);
    }
    let lookup_time = start.elapsed();
    let lookups_per_sec = LOOKUP_ITERS as f64 / lookup_time.as_secs_f64();
    println!("Routing table lookup: {LOOKUP_ITERS} iterations, {lookups_per_sec:.0} lookups/sec");

    // Routing table find_closest is O(n) scan; lower throughput expected\n    assert!(lookups_per_sec > 1000.0, "routing table lookup too slow");
}
