# Current Phase

- Active phase: Phase 5 (in progress)
- Binary target: `saferunnet`
- Activated crates: all 17
- Async runtime: tokio (multi-thread), exposed as RuntimeHandle in saferunnet-core
- Core crates: crypto (Ed25519 + AES-256-GCM), identity (proofs), service (12 protocol families), config, path, dns, dht (Kademlia + network), transport (UDP + handshake + session), link (LLARP frames), router (onion + relay + path build), app kernel (lifecycle + modules)
- Stub crates: platform (TunDevice trait — awaiting WinTunDevice), exit (ExitPolicy trait — awaiting relay wiring), rpc (basic types + JSON-RPC server — awaiting expansion), compat-lokinet (config parser), testing
- All gates pass: `cargo fmt`, `cargo clippy`, `cargo test` clean
- Test count: ~300+ tests, 0 failures
- Phase 5 plan: `docs/superpowers/plans/2026-06-27-saferunnet-phase5-network-daemon.md`
