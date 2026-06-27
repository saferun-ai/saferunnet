# Saferunnet Phase 5 — Network Integration & Daemon Pipeline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.  
> Steps use checkbox (`- [ ]`) syntax for tracking. GPT-5.5 coordinator reviews all work.

**Goal:** Wire the transport, router, DHT, DNS, and exit subsystems into a working daemon. Ship a `saferunnet` binary that can bootstrap from config, connect to peers, route onion packets, resolve `.loki` names, and expose an admin RPC interface.

**Architecture:** Continue composition-first pattern. The daemon binary owns the tokio runtime and wires everything through the AppKernel. Transport runs on UDP. Router uses AES-256-GCM onion encryption. DHT bootstraps from config-listed routers. Platform crate gets its first real implementation: Windows TUN adapter via `wintun`.

**Tech Stack:** Rust stable 2024 edition, tokio, aes-gcm, ed25519-dalek, thiserror, tracing, serde_json (RPC), wintun (Windows TUN)

---

## Task 1: Windows TUN Device Integration

**Files:**
- Create: `crates/saferunnet-platform/src/wintun.rs`
- Modify: `crates/saferunnet-platform/src/lib.rs`
- Modify: `crates/saferunnet-platform/Cargo.toml`
- Modify: `crates/saferunnet-platform/tests/tun_traits.rs`

### Description
Replace `StubTunDevice` with a real `WinTunDevice` that creates a Windows TUN adapter, assigns the configured IP range, and reads/writes IP packets. Use the `wintun` crate for the low-level Windows TUN API.

- [ ] **Step 1: Add `wintun` dependency to platform Cargo.toml**
  - `wintun = "0.4"` (or latest) under `[target."cfg(windows)".dependencies]`
- [ ] **Step 2: Implement `WinTunDevice` struct**
  - Create `crates/saferunnet-platform/src/wintun.rs`
  - `WinTunDevice::create(pool_name: &str, address: &str, netmask: &str, mtu: usize) -> Result<Self, TunError>`
  - Implements `TunDevice` trait (read, write, mtu)
  - On drop, clean up the adapter
- [ ] **Step 3: Add `#[cfg(windows)]` gating in lib.rs**
  - Export `WinTunDevice` on Windows, keep `StubTunDevice` on non-Windows
- [ ] **Step 4: Write tests**
  - Unit test: `WinTunDevice` creation/destruction cycle
  - Unit test: read/write roundtrip with test data
- [ ] **Step 5: Verify**
  - `cargo test -p saferunnet-platform`
  - `cargo clippy -p saferunnet-platform -- -D warnings`

---

## Task 2: Exit Node Policy Enforcement in RelayHandler

**Files:**
- Modify: `crates/saferunnet-router/src/relay.rs`
- Modify: `crates/saferunnet-router/tests/` (add relay_exit test)
- Modify: `crates/saferunnet-exit/src/policy.rs`

### Description
Wire `ExitPolicy` into `RelayHandler::handle_relay_data()` so that exit traffic (frames addressed to an exit node) is filtered against the configured policy. Currently the `exit_policy` field exists but is never consulted during relay.

- [ ] **Step 1: Add `ExitRelayPayload` decoder to exit crate**
  - In `crates/saferunnet-exit/src/exit_relay.rs`, add `parse_exit_target()` if not present
  - Returns `(target_host: String, port: u16)` from a wire-format exit target
- [ ] **Step 2: Wire exit policy check in RelayHandler**
  - In `RelayHandler::handle_relay_data()`: after peeling onion, if the inner frame is `RelayData` destined for exit, parse the exit target and check `exit_policy.allows(target, port)`
  - Return `RelayError::ExitDenied` on policy violation
- [ ] **Step 3: Write tests**
  - Test: `RelayHandler` with `PermitAllPolicy` allows exit traffic
  - Test: `RelayHandler` with `AllowListPolicy(["*.loki:80"])` blocks non-matching exit
  - Test: `RelayHandler` with `None` policy denies all exit traffic
- [ ] **Step 4: Verify**
  - `cargo test -p saferunnet-router`
  - `cargo clippy --workspace -- -D warnings`

---

## Task 3: RPC Admin Interface Expansion

**Files:**
- Modify: `crates/saferunnet-rpc/src/server.rs`
- Modify: `crates/saferunnet-rpc/tests/rpc_tests.rs`

### Description
Expand the JSON-RPC server with more admin methods: `routing_table` (dump DHT routing table), `peers_detail` (list peers with identities), `config_info` (dump current config), and `dht_lookup` (lookup a node by pubkey).

- [ ] **Step 1: Add method handlers**
  - `routing_table`: returns `{ nodes: [...], count: N }`
  - `peers_detail`: returns `{ peers: [{identity, address, sessions}], count: N }`
  - `config_info`: returns `{ router: {...}, network: {...} }`
  - `dht_lookup`: takes `{ "target": "<pubkey_hex>" }`, returns closest nodes
- [ ] **Step 2: Add callback injection points**
  - `RpcServer::with_routing_table(F)` — callback returning Vec of node summaries
  - `RpcServer::with_peers_detail(F)` — callback returning Vec of peer details
  - `RpcServer::with_dht_lookup(F)` — callback for DHT lookup by pubkey
- [ ] **Step 3: Update dispatch() to route new methods**
- [ ] **Step 4: Write tests**
  - Test each new method with mock callbacks
  - Test `dht_lookup` with missing params error
- [ ] **Step 5: Verify**
  - `cargo test -p saferunnet-rpc`

---

## Task 4: Config-Driven Router Pool Bootstrapping

**Files:**
- Modify: `crates/saferunnet-config/src/lib.rs`
- Modify: `crates/saferunnet-dht/src/network.rs`
- Modify: `crates/saferunnet-app/src/` (new bootstrap module or modify path_manager)
- Modify: `apps/saferunnetd/src/main.rs`

### Description
Parse `[router]` bootstrap nodes from config (format: `<pubkey>@<host>:<port>`), feed them into the DHT `NetworkDht::bootstrap()`, and start the background refresh loop in the daemon.

- [ ] **Step 1: Parse bootstrap router list from config**
  - Add `bootstrap_routers: Vec<String>` to `NormalizedConfig.router`
  - Parse `[router] bootstrap = <pubkey>@<host>:<port>` entries
  - Validate format: `<64-hex-chars>@<host>:<port>`
- [ ] **Step 2: Create `BootstrapModule` in saferunnet-app**
  - `BootstrapModule: RuntimeModule` that reads config bootstrap routers
  - On startup, feed nodes into `NetworkDht::bootstrap()`
  - Start background DHT refresh task
- [ ] **Step 3: Wire into main.rs daemon loop**
  - Register `BootstrapModule` in daemon startup
  - Pass config bootstrap routers to module
- [ ] **Step 4: Write tests**
  - Test config parsing of bootstrap router entries
  - Test `BootstrapModule` startup with mock DHT
- [ ] **Step 5: Verify**
  - `cargo test --workspace`
  - `cargo clippy --workspace -- -D warnings`

---

## Task 5: Full Multi-Node Integration Test

**Files:**
- Create: `tests/integration/multi_node.rs`

### Description
Build a simulated 3-node network where each node has its own identity, DHT routing table, and transport. Test: (1) bootstrap nodes discover each other via DHT, (2) build an onion path between node A and C through B, (3) relay a DNS query for `.loki` through the path, (4) verify exit policy enforcement.

- [ ] **Step 1: Set up test harness**
  - 3 `AppKernel` instances with independent identities
  - Mock UDP loopback transport (send/recv between instances via channels)
  - Each with their own DHT, router, exit policy
- [ ] **Step 2: Test DHT bootstrap and discovery**
  - Node A bootstraps to Node B
  - Verify Node C is discoverable through lookup
- [ ] **Step 3: Test onion path build and relay**
  - Build 3-hop path A→B→C
  - Send RelayData frame through path
  - Verify C receives inner payload
- [ ] **Step 4: Test DNS resolution over path**
  - Register `.loki` name in DHT
  - Resolve it through the onion path
- [ ] **Step 5: Test exit policy enforcement**
  - Configure exit node C with `AllowListPolicy(["allowed.loki:80"])`
  - Verify allowed exit permitted, denied exit blocked
- [ ] **Step 6: Verify**
  - `cargo test --test multi_node`

---

## Task 6: Daemon Mode — Async Event Loop

**Files:**
- Modify: `apps/saferunnetd/src/main.rs`
- Modify: `apps/saferunnetd/Cargo.toml`

### Description
Transform the binary from a bootstrap-check tool into a real daemon. Start the tokio runtime, wire all modules, spawn the RPC server, bind the UDP transport, and run until SIGINT.

- [ ] **Step 1: Add `daemon` subcommand**
  - `saferunnet daemon --config <path>` starts full daemon mode
  - Keep `--check-config`, `--bootstrap`, `--check-services` as subcommands
- [ ] **Step 2: Wire the full module graph**
  - Identity → LinkMessage → LinkSessionState → PathManager → DnsResolver
  - Add: TransportModule (UDP binding), DhtModule (bootstrap), RpcModule (admin server)
  - Add: ExitModule (exit policy)
- [ ] **Step 3: Signal handling**
  - On SIGINT (Ctrl+C): graceful shutdown (reverse order)
  - tokio::signal for cross-platform signal handling
- [ ] **Step 4: Logging and stats**
  - Periodic stats dump (peer count, paths active, DHT size)
- [ ] **Step 5: Write integration test**
  - `cargo test --test daemon_lifecycle` (TBD)
- [ ] **Step 6: Verify**
  - `cargo build --bin saferunnet`
  - `saferunnet daemon --config test.ini` runs and accepts Ctrl+C

---

## Completion Criteria

- [ ] All 6 tasks implemented with tests
- [ ] `cargo fmt --all --check`: clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`: clean
- [ ] `cargo test --workspace`: ALL pass, zero failures
- [ ] `cargo build --bin saferunnet --release`: succeeds
- [ ] Phase 5 checklist in roadmap.md marked complete
