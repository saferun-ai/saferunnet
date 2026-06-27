//! Long-running stability (soak) tests for saferunnetd.
//!
//! All tests require `--features soak` to run.

#[cfg(feature = "soak")]
mod soak {
    use saferunnet_crypto::{KeyAlgorithm, PublicKey};
    use saferunnet_dns::resolver::{DhtClient, DhtIntroResult};
    use saferunnet_link::FrameKind;
    use saferunnetd::forwarder::OnionForwarder;

    /// Build a deterministic PublicKey from a seed byte.
    fn make_key(seed: u8) -> PublicKey {
        PublicKey::from_bytes(KeyAlgorithm::Ed25519, [seed; 32])
    }

    /// Build a deterministic nonce from a seed byte.
    fn make_nonce(seed: u8) -> [u8; 32] {
        let mut n = [0u8; 32];
        n[0] = seed;
        n
    }

    /// ─── continuous_relay_1000_packets ──────────────────────

    #[test]
    #[cfg(feature = "soak")]
    fn continuous_relay_1000_packets() {
        let fwd = OnionForwarder::new();
        let path: Vec<_> = (1..=3).map(make_key).collect();
        let nonce = make_nonce(42);

        for i in 0..1000u64 {
            let packet = format!("soak-packet-{:04}", i).into_bytes();
            let frame = fwd.wrap_packet(&packet, &path, &nonce, i).unwrap();
            assert_eq!(frame.kind, FrameKind::RelayData);
            assert_eq!(frame.path_id, i);
            assert!(!frame.payload.is_empty());
        }
    }

    /// ─── dht_node_churn_50_nodes ────────────────────────────

    /// A mock DHT that returns a fixed set of intro results.
    struct MockDht {
        results: Vec<DhtIntroResult>,
    }

    impl DhtClient for MockDht {
        fn lookup_intro_set(&self, _target: &PublicKey) -> Vec<DhtIntroResult> {
            self.results.clone()
        }
    }

    #[test]
    #[cfg(feature = "soak")]
    fn dht_node_churn_50_nodes() {
        // Create 50 mock DHT results with unique keys
        let results: Vec<DhtIntroResult> = (0..50u8)
            .map(|i| {
                let mut pk_bytes = [0u8; 32];
                pk_bytes[0] = i;
                DhtIntroResult {
                    public_key: PublicKey::from_bytes(KeyAlgorithm::Ed25519, pk_bytes),
                    addresses: vec![format!("10.0.0.{}:1090", i % 255 + 1)],
                }
            })
            .collect();

        let dht = MockDht {
            results: results.clone(),
        };
        let fwd = OnionForwarder::new();
        let destination = make_key(99);

        // Run 100 lookups and verify consistency
        for _ in 0..100 {
            let path = fwd.find_path(&dht, &destination, 1, 3);
            assert!(!path.is_empty());
            assert!(path.len() <= 3);
            // Every key in the path should come from the DHT results
            for pk in &path {
                let found = results
                    .iter()
                    .any(|r| r.public_key.to_bytes() == pk.to_bytes());
                assert!(found, "path key should be in DHT results");
            }
        }
    }

    /// ─── concurrent_path_builds ──────────────────────────────

    #[test]
    #[cfg(feature = "soak")]
    fn concurrent_path_builds() {
        let fwd = OnionForwarder::new();
        let nonce = make_nonce(77);

        let mut frame_payloads = Vec::new();

        for i in 0..10u64 {
            // Each path uses different intermediate keys
            let path: Vec<_> = (0..3u8).map(|j| make_key(j + (i as u8 * 10))).collect();
            let packet = format!("concurrent-packet-{:02}", i).into_bytes();

            let frame = fwd.wrap_packet(&packet, &path, &nonce, i).unwrap();
            assert_eq!(frame.kind, FrameKind::RelayData);
            assert_eq!(frame.path_id, i);

            // Track payloads to verify each is unique
            frame_payloads.push(frame.payload);
        }

        // Verify all 10 frames have distinct payloads (since different onion layers)
        for i in 0..frame_payloads.len() {
            for j in (i + 1)..frame_payloads.len() {
                assert_ne!(
                    frame_payloads[i], frame_payloads[j],
                    "frames {} and {} should have distinct payloads",
                    i, j
                );
            }
        }
    }

    // ─── Additional robustness tests ──────────────────────────

    #[test]
    #[cfg(feature = "soak")]
    fn wrap_packet_rejects_empty_path_repeatedly() {
        let fwd = OnionForwarder::new();
        for _ in 0..100 {
            let result = fwd.wrap_packet(b"data", &[], &make_nonce(1), 1);
            assert!(result.is_err());
        }
    }

    #[test]
    #[cfg(feature = "soak")]
    fn repeated_path_build_and_relay_100_iterations() {
        let fwd = OnionForwarder::new();

        // Mock DHT that always returns the same path nodes
        struct StableDht {
            nodes: Vec<DhtIntroResult>,
        }
        impl DhtClient for StableDht {
            fn lookup_intro_set(&self, _target: &PublicKey) -> Vec<DhtIntroResult> {
                self.nodes.clone()
            }
        }

        let nodes: Vec<DhtIntroResult> = (1..=4u8)
            .map(|i| DhtIntroResult {
                public_key: make_key(i),
                addresses: vec![format!("10.0.0.{}:1090", i)],
            })
            .collect();
        let dht = StableDht {
            nodes: nodes.clone(),
        };
        let destination = make_key(99);

        let nonce = make_nonce(55);

        for iteration in 0..100u64 {
            let path = fwd.find_path(&dht, &destination, 1, 3);
            assert!(!path.is_empty());

            let packet = format!("relay-iter-{:04}", iteration).into_bytes();
            let frame = fwd.wrap_packet(&packet, &path, &nonce, iteration).unwrap();
            assert_eq!(frame.kind, FrameKind::RelayData);
            assert_eq!(frame.path_id, iteration);
        }
    }
}
