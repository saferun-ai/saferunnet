# Saferunnet Phase 7 — Production Hardening & Integration Completion

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.  
> Steps use checkbox (`- [ ]`) syntax for tracking. GPT-5.5 coordinator reviews all work.

**Goal:** Complete the remaining production gaps: real DNS response construction, OnionForwarder TUN wiring, Windows service verification, soak tests, and comprehensive documentation.

**Architecture:** The daemon binary (`apps/saferunnetd/src/main.rs`) owns the TUN loop. `handle_dns_query()` currently parses .loki queries but returns empty stubs. `OnionForwarder` exists but is not wired into non-DNS packet routing. Both must be completed with tests.

**Tech Stack:** Rust stable 2024 edition, tokio, ed25519-dalek, aes-gcm, serde, thiserror, tracing.

---

## Task 1: TUN DNS Response Construction

**Files:**
- Modify: `apps/saferunnetd/src/main.rs`
- Modify: `apps/saferunnetd/tests/cli.rs` (extend DNS response tests)

### Description
Complete `handle_dns_query()` to construct real DNS response packets when .loki names resolve via DHT. Currently the function parses queries and finds names but returns `None` for resolvable names. The response must be a valid DNS UDP payload with the resolved IP.

- [ ] **Step 1: Implement `build_dns_response()` helper**
  - Takes `dns_id: u16`, `resolved_ip: [u8; 4]`, and original DNS question section
  - Builds RFC 1035-compliant response: copy header, set QR=1 (response), RA=1 (recursion available), set ANCOUNT=1
  - Answer section: name pointer (0xC00C), type A (0x0001), class IN (0x0001), TTL 60, RDLENGTH 4, RDATA = resolved_ip
- [ ] **Step 2: Wire DHT resolution into `handle_dns_query()`**
  - After parsing .loki name from DNS query, call `dht.resolve(&loki_name).await`
  - On successful resolution, call `build_dns_response()` and return Some(response)
  - On resolution failure, return NXDOMAIN response (RCODE=3)
- [ ] **Step 3: Handle `handle_dns_query` async conversion**
  - Currently `handle_dns_query()` is synchronous; DHT resolution requires async
  - Option A: make it async, adjust `run_tun_loop` to use `block_in_place` or spawn
  - Option B: spawn a tokio task for resolution, use a oneshot channel
  - Prefer Option B to keep the blocking TUN reader simple
- [ ] **Step 4: Write tests**
  - Unit test: `build_dns_response()` produces valid DNS wire format with correct IP
  - Unit test: `build_dns_response()` with different IDs preserves ID
  - Integration test: mock DHT returns resolved IP, verify full DNS response
  - Integration test: mock DHT fails resolution, verify NXDOMAIN response
- [ ] **Step 5: Verify**
  - `cargo test -p saferunnetd`
  - `cargo clippy -p saferunnetd -- -D warnings`

---

## Task 2: OnionForwarder TUN Loop Integration

**Files:**
- Modify: `apps/saferunnetd/src/forwarder.rs`
- Modify: `apps/saferunnetd/src/main.rs`
- Modify: `apps/saferunnetd/tests/multi_node_integration.rs`

### Description
Wire `OnionForwarder` into the non-DNS branch of `run_tun_loop()`. Currently non-DNS packets are echoed back. Instead, they should be wrapped in onion layers using an active path and relayed through the network.

- [ ] **Step 1: Add `OnionForwarder::resolve_and_forward()` method**
  - Accepts raw IP packet, active path (Vec<PublicKey>), nonce, path_id
  - Wraps in onion layers via `self.onion.wrap()`
  - Produces `LlarpFrame` ready for relay
  - Returns frame bytes or error
- [ ] **Step 2: Add path lookup to OnionForwarder**
  - `OnionForwarder::find_exit_path(&self, dht: &dyn DhtClient) -> Option<Vec<PublicKey>>`
  - Finds closest nodes to destination via DHT lookup
  - Returns path of public keys (3-hop default)
- [ ] **Step 3: Wire into run_tun_loop()**
  - In the `!is_dns_packet(packet)` branch, instead of echoing:
  - Call `forwarder.find_exit_path(dht)` to get a path
  - Call `forwarder.resolve_and_forward(packet, path, ...)` to build frame
  - Send frame via relay (for now, log and continue; actual relay transmission is next phase)
- [ ] **Step 4: Write tests**
  - Test: `OnionForwarder::resolve_and_forward()` produces non-empty frame
  - Test: `OnionForwarder::resolve_and_forward()` with empty path returns error
  - Test: `OnionForwarder::find_exit_path()` returns path from DHT
  - Integration test: non-DNS packet flows through OnionForwarder
- [ ] **Step 5: Verify**
  - `cargo test -p saferunnetd`
  - `cargo clippy -p saferunnetd -- -D warnings`

---

## Task 3: Windows Service Integration Testing

**Files:**
- Modify: `apps/saferunnetd/src/main.rs`
- Create: `apps/saferunnetd/tests/windows_service.rs`

### Description
Verify the `--service-install` and `--service-uninstall` CLI flags work correctly on Windows. Add integration tests that validate the Windows Service Control Manager (SCM) interactions.

- [ ] **Step 1: Add `--service-status` CLI flag**
  - Queries SCM for the saferunnet service status
  - Reports: running, stopped, not installed
- [ ] **Step 2: Improve service install error handling**
  - Check for admin privileges before attempting install
  - Report clear error if not running as admin
  - Handle service-already-exists gracefully
- [ ] **Step 3: Write service tests**
  - Test: `--service-install` help text is correct
  - Test: `--service-uninstall` help text is correct
  - Test: `--service-status` reports not-installed when no service exists
  - Test: service install creates SCM entry (requires admin, mark as `#[ignore]`)
- [ ] **Step 4: Verify**
  - `cargo test -p saferunnetd`
  - `cargo clippy -p saferunnetd -- -D warnings`

---

## Task 4: Soak Test Infrastructure

**Files:**
- Create: `apps/saferunnetd/tests/soak.rs`
- Modify: `crates/saferunnet-testing/src/lib.rs` (add timeout helpers)

### Description
Add long-running soak tests that validate the system under sustained load: continuous packet relay, DHT churn, concurrent path builds.

- [ ] **Step 1: Add test timeout helpers to saferunnet-testing**
  - `run_with_timeout(duration, future)` — runs a future with a deadline
  - `assert_completes_within(duration, future)` — panics if future times out
- [ ] **Step 2: Create soak test suite**
  - Test: 30-second continuous relay (1000 packets through 3-hop path)
  - Test: DHT node churn (add/remove 50 nodes over 10 seconds, verify lookups)
  - Test: concurrent path builds (10 simultaneous 3-hop path builds)
  - Test: memory stability (run relay loop, check memory doesn't grow unbounded)
- [ ] **Step 3: Add soak test runner**
  - Provide `#[cfg(feature = "soak")]` gating so soak tests only run on demand
  - Add `cargo test --features soak` as documented command
- [ ] **Step 4: Verify**
  - `cargo test -p saferunnetd --features soak` (or regular tests if soak is default)
  - `cargo clippy --workspace -- -D warnings`

---

## Task 5: Comprehensive Documentation

**Files:**
- Create: `docs/ARCHITECTURE.md`
- Create: `docs/API.md`
- Create: `docs/GETTING_STARTED.md`
- Modify: `README.md` (if exists)

### Description
Write comprehensive documentation covering: architecture overview, crate dependency graph, module responsibilities, API reference, and developer getting-started guide.

- [ ] **Step 1: Write ARCHITECTURE.md**
  - Crate dependency graph (ASCII art or mermaid)
  - Module composition pattern (RuntimeModule, ServiceRegistry, AppKernel)
  - Data flow: TUN → DNS/Onion→ DHT → Transport
  - Security model: identity (Ed25519), encryption (AES-256-GCM), exit policy
- [ ] **Step 2: Write API.md**
  - Crate-level API documentation for each of the 17 crates
  - Key traits: RuntimeModule, TunDevice, ExitPolicy, DhtClient, LinkTransport
  - Configuration format reference
- [ ] **Step 3: Write GETTING_STARTED.md**
  - Prerequisites: Rust toolchain, Windows (for TUN)
  - Build instructions: `cargo build --release`
  - Configuration: minimal config example, all options
  - Running: daemon mode, service mode, bootstrap
- [ ] **Step 4: Update README.md**
  - Brief project description
  - Links to docs
  - Quick start
- [ ] **Step 5: Verify**
  - Read through all docs for accuracy
  - Check all file paths and commands are correct

---

## Completion Criteria

- [ ] All 5 tasks implemented with tests
- [ ] `cargo fmt --all --check`: clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`: clean
- [ ] `cargo test --workspace`: ALL pass, zero failures
- [ ] `cargo build --bin saferunnet --release`: succeeds
- [ ] Phase 7 checklist in roadmap.md marked complete