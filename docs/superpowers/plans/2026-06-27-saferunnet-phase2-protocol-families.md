# Saferunnet Phase 2 — Protocol Families & Subsystem Activation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the typed protocol family surface, activate remaining stub crates (dns, path), harden kernel contracts, and deliver a runtime that can build/verify paths and resolve .loki names.

**Architecture:** Continue the convergence pattern: typed protocol families live in `saferunnet-service`, runtime modules live in `saferunnet-app`. New crates (`saferunnet-path`, `saferunnet-dns`) expose traits with the composition-first pattern. Kernel dependency contracts graduate from string keys to typed descriptors.

**Tech Stack:** Rust stable, `thiserror`, `tracing`, `ed25519-dalek`, `rand_core`, `zeroize`, `arrayvec` (for fixed-size protocol framing), `hex`

---

### Task A: Typed Kernel Dependency Contracts

**Files:**
- Modify: `crates/saferunnet-core/src/module.rs`
- Modify: `crates/saferunnet-core/src/service.rs`
- Modify: `crates/saferunnet-app/src/kernel.rs`
- Modify: `crates/saferunnet-app/src/identity.rs`
- Modify: `crates/saferunnet-app/src/link.rs`
- Modify: `crates/saferunnet-app/tests/kernel_lifecycle.rs`
- Modify: `crates/saferunnet-app/tests/link_message_module.rs`
- Modify: `crates/saferunnet-app/tests/link_session_state_module.rs`

- [ ] **Step 1: Add `ServiceKey` typed descriptor to core**

Replace string-key service lookups with a `ServiceKey` struct that carries a type-id discriminant and a display name. Write the failing test first.

```rust
// In crates/saferunnet-core/src/service.rs, add:
use std::any::TypeId;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceKey {
    type_id: TypeId,
    name: &'static str,
}

impl ServiceKey {
    pub fn of<T: 'static>(name: &'static str) -> Self {
        Self { type_id: TypeId::of::<T>(), name }
    }

    pub fn name(&self) -> &'static str { self.name }
}
```

Migrate `ServiceRegistry` to use `ServiceKey` instead of `&'static str` for lookups.

- [ ] **Step 2: Update `RuntimeModule` trait**

```rust
pub trait RuntimeModule {
    fn name(&self) -> &'static str;
    fn register_services(&mut self, _services: &mut ServiceRegistry) -> Result<(), ModuleError> { Ok(()) }
    fn required_service_keys(&self) -> &[ServiceKey] { &[] }
    fn wire(&mut self, _services: &ServiceRegistry) -> Result<(), ModuleError> { Ok(()) }
    fn start(&mut self) -> Result<(), ModuleError>;
    fn stop(&mut self) -> Result<(), ModuleError>;
}
```

Replace `required_service_keys() -> &'static [&'static str]` with `-> &[ServiceKey]`.

- [ ] **Step 3: Update kernel to use `ServiceKey`**

Update `AppKernel::start()` to use `ServiceKey` for dependency checks. Update all module implementations (`IdentityModule`, `LinkMessageModule`, `LinkSessionStateModule`) to return `ServiceKey` arrays.

- [ ] **Step 4: Migrate all tests**

Update test code that uses the old string-key constants (`NODE_IDENTITY_SERVICE_KEY`, `LINK_MESSAGE_DISPATCHER_SERVICE_KEY`, `LINK_SESSION_STATE_SERVICE_KEY`) to use `ServiceKey::of::<T>()`.

- [ ] **Step 5: Verify**

```powershell
cargo test -p saferunnet-core
cargo test -p saferunnet-app --test kernel_lifecycle
cargo test -p saferunnet-app --test link_message_module
cargo test -p saferunnet-app --test link_session_state_module
```

Expected: ALL PASS

---

### Task B: DHT Intro Message Family

**Files:**
- Create: `crates/saferunnet-service/src/dht_intro.rs`
- Modify: `crates/saferunnet-service/src/lib.rs`
- Create: `crates/saferunnet-service/tests/dht_intro.rs`
- Modify: `crates/saferunnet-service/Cargo.toml`

- [ ] **Step 1: Add `ServiceMessageKind::DhtIntro`**

In `crates/saferunnet-service/src/lib.rs`, add:
```rust
pub enum ServiceMessageKind {
    // ... existing ...
    DhtIntro,
}
```
Update `encode_kind`/`decode_kind` with variant `8`.

- [ ] **Step 2: Write DHT intro payload types**

In `crates/saferunnet-service/src/dht_intro.rs`:
```rust
use arrayvec::ArrayVec;
use saferunnet_crypto::PublicKey;
use thiserror::Error;

pub const MAX_DHT_INTRO_ADDRESSES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily { Ipv4, Ipv6 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtIntroEntry {
    pub public_key: PublicKey,
    pub family: AddressFamily,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtIntroMessage {
    pub entries: ArrayVec<DhtIntroEntry, MAX_DHT_INTRO_ADDRESSES>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedDhtIntroMessage {
    inner: crate::AuthenticatedServiceMessage,
    payload: DhtIntroMessage,
}

#[derive(Debug, Error)]
pub enum DhtIntroError {
    #[error("no entries present")]
    Empty,
    #[error("{0}")]
    Service(#[from] crate::ServiceMessageError),
}
```

- [ ] **Step 3: Implement codec (encode/decode/verify)**

Implement deterministic framing for DHT intro payloads:
- Version byte
- Entry count (u8)
- Per entry: pubkey (32 bytes) + family (1 byte) + port (2 bytes BE)
- Reject: empty, overflow (>8), unsupported version, trailing bytes

- [ ] **Step 4: Write tests**

```powershell
cargo test -p saferunnet-service dht_intro
```
Expected: PASS with sign/verify round-trip, encode/decode round-trip, wrong-kind rejection, tamper rejection, empty rejection, overflow rejection

---

### Task C: Path Build Message Family

**Files:**
- Create: `crates/saferunnet-service/src/path_build.rs`
- Modify: `crates/saferunnet-service/src/lib.rs`
- Create: `crates/saferunnet-service/tests/path_build.rs`

- [ ] **Step 1: Add `ServiceMessageKind::LinkPathBuild`**

Variant `9` in encode/decode kind tables.

- [ ] **Step 2: Write path build payload types**

```rust
pub struct PathHop {
    pub router_id: PublicKey,
}

pub struct PathBuildMessage {
    pub path_id: u64,
    pub hops: ArrayVec<PathHop, 8>,
}

pub struct PathBuildResponse {
    pub path_id: u64,
    pub accepted: bool,
}

pub struct AuthenticatedPathBuildMessage { /* wrapper over AuthenticatedServiceMessage */ }
pub struct AuthenticatedPathBuildResponse { /* wrapper */ }
```

- [ ] **Step 3: Implement codec with tests**

Follow same pattern as existing families: versioned framing, authenticated wrapper, verify-then-decode.

---

### Task D: Transit Hop Message Family

**Files:**
- Create: `crates/saferunnet-service/src/transit_hop.rs`
- Modify: `crates/saferunnet-service/src/lib.rs`
- Create: `crates/saferunnet-service/tests/transit_hop.rs`

- [ ] **Step 1: Add `ServiceMessageKind::LinkTransitHop`**

Variant `10`.

- [ ] **Step 2: Write transit hop payload types**

```rust
pub struct TransitHopMessage {
    pub path_id: u64,
    pub hop_index: u8,
    pub encrypted_payload: Vec<u8>,
}

pub struct AuthenticatedTransitHopMessage { /* wrapper */ }
```

- [ ] **Step 3: Implement with tests**

Same pattern: versioned framing, encode/decode, wrong-kind, tamper, truncated, trailing rejection.

---

### Task E: Activate `saferunnet-path` Crate

**Files:**
- Create: `crates/saferunnet-path/Cargo.toml`
- Create: `crates/saferunnet-path/src/lib.rs`
- Create: `crates/saferunnet-path/src/build.rs`
- Create: `crates/saferunnet-path/src/select.rs`
- Create: `crates/saferunnet-path/src/health.rs`
- Create: `crates/saferunnet-path/tests/path_lifecycle.rs`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 1: Scaffold the crate**

```toml
[package]
name = "saferunnet-path"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
saferunnet-core = { path = "../saferunnet-core" }
saferunnet-crypto = { path = "../saferunnet-crypto" }
thiserror.workspace = true
tracing.workspace = true

[dev-dependencies]
saferunnet-testing = { path = "../saferunnet-testing" }
```

- [ ] **Step 2: Define path traits**

```rust
// lib.rs
pub mod build;
pub mod select;
pub mod health;

pub trait PathBuilder {
    fn build_path(&mut self, target: &saferunnet_crypto::PublicKey, hops: usize) -> Result<PathDescriptor, PathError>;
}

pub trait PathSelector {
    fn select_path(&self, target: &saferunnet_crypto::PublicKey) -> Option<PathDescriptor>;
}

#[derive(Debug, Clone)]
pub struct PathDescriptor {
    pub path_id: u64,
    pub hops: Vec<saferunnet_crypto::PublicKey>,
    pub state: PathState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState { Building, Established, Failing, Dead }
```

- [ ] **Step 3: Implement first concrete selector**

Implement a random-path selector that picks n unique routers from a provided pool.

- [ ] **Step 4: Add path health trait + round-robin pinger**

```rust
pub trait PathHealthChecker {
    fn check(&mut self, path: &PathDescriptor) -> PathState;
}
```

- [ ] **Step 5: Write tests**

```powershell
cargo test -p saferunnet-path
```

---

### Task F: Activate `saferunnet-dns` Crate

**Files:**
- Create: `crates/saferunnet-dns/Cargo.toml`
- Create: `crates/saferunnet-dns/src/lib.rs`
- Create: `crates/saferunnet-dns/src/resolver.rs`
- Create: `crates/saferunnet-dns/src/loki.rs`
- Create: `crates/saferunnet-dns/tests/resolver.rs`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 1: Scaffold the crate**

```toml
[package]
name = "saferunnet-dns"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
saferunnet-core = { path = "../saferunnet-core" }
saferunnet-crypto = { path = "../saferunnet-crypto" }
thiserror.workspace = true
tracing.workspace = true

[dev-dependencies]
saferunnet-testing = { path = "../saferunnet-testing" }
```

- [ ] **Step 2: Define DNS resolver trait**

```rust
pub trait LokiResolver {
    fn resolve(&self, name: &str) -> Result<Vec<saferunnet_crypto::PublicKey>, DnsError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("not a .loki name: {0}")]
    NotLokiName(String),
    #[error("name not found: {0}")]
    NotFound(String),
}
```

- [ ] **Step 3: Implement .loki name parser**

Parse `xxx.loki` names. Reject non-`.loki` suffixes. Validate allowed characters.

- [ ] **Step 4: Implement stub resolver**

Implement a stub resolver that maintains a static mapping (for testing) and exposes the `LokiResolver` trait.

- [ ] **Step 5: Write tests**

```powershell
cargo test -p saferunnet-dns
```

---

### Task G: Kernel Rollback Hardening & Error Categories

**Files:**
- Modify: `crates/saferunnet-core/src/module.rs`
- Modify: `crates/saferunnet-core/src/lifecycle.rs`
- Modify: `crates/saferunnet-app/src/kernel.rs`
- Modify: `crates/saferunnet-app/tests/kernel_lifecycle.rs`

- [ ] **Step 1: Add richer `ModuleError` variants**

```rust
#[derive(Debug, Error)]
pub enum ModuleError {
    #[error("module lifecycle violation: {0}")]
    Lifecycle(String),
    #[error("module `{module}`: service registration failed: {reason}")]
    ServiceRegistration { module: &'static str, reason: String },
    #[error("module `{module}`: wire failed: {reason}")]
    Wiring { module: &'static str, reason: String },
    #[error("module `{module}`: start failed: {reason}")]
    Startup { module: &'static str, reason: String },
    #[error("module `{module}`: stop failed: {reason}")]
    Shutdown { module: &'static str, reason: String },
}
```

- [ ] **Step 2: Add service-registration rollback**

In `AppKernel::start()`, after `register_services()` loop, if a later module fails registration or wiring, rollback registered services from earlier modules.

- [ ] **Step 3: Write rollback tests**

Test that service-registration failures cause rollback of already-registered services. Test that wiring failures rollback service registrations.

- [ ] **Step 4: Verify**

```powershell
cargo test -p saferunnet-app --test kernel_lifecycle
```

---

### Task H: Cross-Crate Integration & Full Verification

**Files:**
- Modify: `docs/status/current-phase.md`
- Modify: `docs/status/roadmap.md`
- Modify: `docs/status/modules/*.md`
- Create: `docs/status/session-log/2026-06-27.md`

- [ ] **Step 1: Run full test suite**

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- [ ] **Step 2: Update status ledgers**

Update `current-phase.md` to reflect Phase 2 progress. Update module status files for path, dns, router, link, service. Create session log `2026-06-27.md`.

- [ ] **Step 3: Record verification evidence**

Run final `./scripts/check.ps1` and log results.

---

## Task Dependency Graph

```
Task A (kernel contracts) ── independent, blocks nothing
Task B (DHT intro)         ── independent
Task C (path build)        ── independent
Task D (transit hop)       ── independent
Task E (path crate)        ── depends on C
Task F (dns crate)         ── independent
Task G (kernel hardening)  ── depends on A
Task H (integration)       ── depends on ALL

Parallel groups:
  Wave 1: A, B, C, D (all independent)
  Wave 2: E, F, G (depend on wave 1)
  Wave 3: H (final integration)
```

## Subagent Dispatch Plan

| Wave | Task | Agent | Model |
|------|------|-------|-------|
| 1 | A: Kernel Contracts | Worker A | gpt-5.3-codex |
| 1 | B: DHT Intro | Worker B | gpt-5.4 |
| 1 | C: Path Build | Worker C | gpt-5.4 |
| 1 | D: Transit Hop | Worker D | gpt-5.3-codex |
| 2 | E: Path Crate | Worker E | gpt-5.4 |
| 2 | F: DNS Crate | Worker F | gpt-5.4 |
| 2 | G: Kernel Hardening | Worker G | gpt-5.3-codex |
| 3 | H: Integration | Coordinator | gpt-5.5 |

Each worker follows: test-first → implement → verify → report.
Coordinator reviews each wave, requests rework if needed.
