# Saferunnet Rust Rewrite Design

**Date:** 2026-06-25

**Status:** Approved baseline, pending final user review of written spec

## 1. Overview

`saferunnet` is a full Rust rewrite of Lokinet-oriented functionality for the local Saferunnet environment. The rewrite prioritizes maintainability, explicit module boundaries, lower dependency fragmentation, test-first delivery, and a flatter composition-oriented architecture instead of deep inheritance or god objects.

This project will keep compatibility with Lokinet configuration and operational behavior where compatibility is valuable, while intentionally improving internal structure, type safety, testability, and extensibility.

## 2. Goals

1. Build a Rust-first replacement whose compiled binary name is `saferunnet`.
2. Avoid dependency sprawl by preferring a curated dependency set, internal abstractions, and project-owned submodules when third-party crates are too fragmented or unstable.
3. Use an architecture that is friendly to change:
   - composition over inheritance
   - explicit capabilities and traits at subsystem boundaries
   - narrow interfaces
   - isolated platform adapters
   - no central god object that owns all runtime state
4. Require tests for every implemented module and every delivered feature slice.
5. Preserve Lokinet-compatible configuration semantics where doing so reduces migration cost, while allowing cleaner internal representation and better validation.
6. Support a subagent-cluster workflow:
   - GPT-5.5 for architecture, planning, acceptance, and review
   - GPT-5.4 or GPT-5.3-Codex for implementation tasks
   - GPT-5.5 review and forced rework when tasks fail spec or quality review
7. Make every iteration resumable by leaving behind implementation status, unfinished scope, and next-step context for later sessions.

## 3. Non-Goals

1. Do not aim for a line-by-line transliteration of the C++ codebase.
2. Do not preserve problematic upstream structure merely for familiarity.
3. Do not optimize for maximal crate diversity or experimental dependencies.
4. Do not build the full protocol surface in one pass without stage gates and tests.

## 4. Architecture Principles

### 4.1 Composition-First Runtime

The runtime will be assembled from focused services rather than inherited class trees. Each subsystem exposes a stable contract and receives only the dependencies it needs.

Examples of intended boundaries:

- `AppKernel` owns startup, shutdown, dependency wiring, and lifecycle orchestration.
- `ConfigService` loads, validates, normalizes, and emits typed configuration.
- `IdentityService` owns key material, identity loading, and crypto policy.
- `LinkService` owns transport/link establishment.
- `PathService` owns path construction and path health.
- `RouterService` owns routing decisions and message dispatch contracts.
- `NameService` owns DNS and `.loki`-style lookup behavior.
- `ExitService` owns exit-node-facing behavior behind a dedicated interface.
- `PlatformService` owns TUN/VPN and OS integration through adapter traits.

### 4.2 Change-Oriented Design

Subsystem contracts must be designed around expected change:

- transport implementation changes
- path selection policy changes
- crypto backend replacement
- platform adapter changes
- configuration schema evolution
- test-only fakes and simulators

This means:

- no direct cross-module state mutation
- no hidden singleton state
- no subsystem reaching through another subsystem's internals
- interfaces shaped around use-cases, not data dumping

### 4.3 Flat Inheritance Strategy

Where polymorphism is needed, use traits plus composition rather than deep inheritance trees. Trait hierarchies should remain shallow and capability-specific.

Allowed examples:

- `Transport`
- `PacketCodec`
- `PathSelector`
- `Clock`
- `KeyStore`
- `DnsResolver`
- `TunDevice`

Disallowed pattern:

- one base runtime type with dozens of optional hooks and subclasses overriding behavior implicitly

### 4.4 Strong Separation of Core and Adapters

The codebase must distinguish:

- pure domain/core logic
- runtime orchestration
- I/O and network adapters
- platform adapters
- compatibility translators
- observability and operator tooling

Core logic must remain testable without real sockets, tun devices, or filesystem state.

## 5. Phase Strategy

The approved delivery strategy is `runtime skeleton first`, followed by protocol and system capabilities in stages.

### Phase 0: Governance and Foundation

Deliverables:

- Rust workspace and crate layout
- binary target name `saferunnet`
- dependency policy and crate selection rules
- lint/test/format/bench configuration
- status-tracking and resumability files
- subagent execution workflow

Exit criteria:

- workspace builds
- CI-local commands are defined
- status ledger format exists
- architectural boundaries are documented

### Phase 1: Configuration and Application Kernel

Deliverables:

- Lokinet-compatible config ingestion
- typed normalized config model
- startup/shutdown lifecycle model
- service registry/module wiring
- structured error taxonomy
- structured logging/metrics/tracing hooks

Exit criteria:

- sample config loads successfully
- invalid config produces actionable diagnostics
- module lifecycle is test-covered

### Phase 2: Identity and Crypto

Deliverables:

- key generation/loading
- key storage abstraction
- signature and encryption interfaces
- deterministic test vectors
- crypto provider abstraction

Exit criteria:

- identity persistence is covered by tests
- crypto contracts are provider-agnostic
- no crypto call sites bypass the abstraction layer

### Phase 3: Link, Path, and Routing Core

Deliverables:

- transport abstraction
- link/session establishment
- packet codec layer
- path construction and maintenance
- routing message handling
- router state decomposition into focused components

Exit criteria:

- simulated multi-node scenarios pass
- routing components are split by responsibility
- no single router component owns all mutable state

### Phase 4: Service Plane

Deliverables:

- DHT-facing integration layer
- `.loki`/service naming support
- service session management
- exit-service backend behavior
- control/RPC surfaces needed for operators

Exit criteria:

- service-level integration tests pass
- name lookup and service routing contracts are isolated and mockable

### Phase 5: System Integration

Deliverables:

- DNS adapter
- TUN/VPN adapter layer
- platform-specific networking integration
- compatibility behavior tuning
- performance regression harness

Exit criteria:

- platform adapters are behind traits
- integration tests cover DNS/VPN critical paths
- compatibility deviations are documented and intentional

### Phase 6: Stabilization and Migration Readiness

Deliverables:

- interoperability matrix
- config migration notes
- performance baselines
- operational runbooks
- release packaging and distribution shape

Exit criteria:

- known gaps are documented
- migration steps are explicit
- readiness report exists

## 6. Dependency Strategy

### 6.1 Dependency Policy

Dependencies must be intentionally curated. A crate is acceptable only if it clearly reduces maintenance cost without introducing fragmented transitive behavior or unstable ownership.

Use the following order:

1. Rust standard library
2. Mature, high-signal crates with clear ownership and healthy maintenance
3. Small internal crate inside the workspace
4. Vendored or submodule-owned implementation when the ecosystem option is too fragmented

### 6.2 Expected Shared Infrastructure

The project should centralize common concerns rather than solving them repeatedly:

- config parsing
- error handling
- logging/tracing
- async runtime policy
- serialization formats
- test fixtures
- simulation support

### 6.3 Internal Before Fragmented External

If a required capability would pull in multiple poorly aligned crates, prefer implementing a minimal internal crate with a narrow API. This is especially relevant for:

- compatibility parsing
- protocol codecs
- specialized path/routing simulation helpers
- platform shim glue

## 7. Proposed Source Tree

The directory structure must reflect boundaries, not language trivia. The initial workspace should look like this:

```text
saferunnet/
  Cargo.toml
  Cargo.lock
  crates/
    saferunnet-app/
    saferunnet-config/
    saferunnet-core/
    saferunnet-crypto/
    saferunnet-identity/
    saferunnet-link/
    saferunnet-path/
    saferunnet-router/
    saferunnet-service/
    saferunnet-exit/
    saferunnet-dns/
    saferunnet-platform/
    saferunnet-rpc/
    saferunnet-observability/
    saferunnet-testing/
    saferunnet-compat-lokinet/
  apps/
    saferunnetd/
    saferunnetctl/
  tests/
    integration/
    interoperability/
    fixtures/
  docs/
    architecture/
    decisions/
    superpowers/
      specs/
      plans/
    status/
  scripts/
  vendor/
```

### 7.1 Directory Rules

1. `crates/` contains reusable implementation crates only.
2. `apps/` contains top-level binaries and thin entrypoints.
3. `tests/integration/` contains cross-crate behavior checks.
4. `tests/interoperability/` contains compatibility and upstream-behavior validation.
5. `docs/status/` contains resumability records.
6. `vendor/` is reserved for owned third-party code or submodules that the team intentionally absorbs.

### 7.2 Anti-Sprawl Rules

1. Do not create a crate per tiny abstraction.
2. Do not let `saferunnet-core` become a dumping ground.
3. Move platform-specific code into `saferunnet-platform` adapters.
4. Keep protocol compatibility parsing in `saferunnet-compat-lokinet`.
5. Promote shared test fixtures into `saferunnet-testing` instead of duplicating helpers.

## 8. Configuration Compatibility Strategy

Configuration should remain operator-friendly for users familiar with Lokinet, but internal code should only consume a normalized, typed configuration model.

Flow:

1. Read source config from Lokinet-compatible format.
2. Parse into a compatibility-layer representation.
3. Validate and normalize into internal typed settings.
4. Emit warnings for deprecated or risky inputs.
5. Pass only normalized settings into runtime services.

This preserves compatibility without contaminating runtime code with legacy parsing rules.

## 9. Testing Strategy

### 9.1 Universal Rule

No module or feature is considered implemented until tests for that scope exist and pass.

### 9.2 Test Layers

1. Unit tests
   - pure logic
   - config normalization
   - routing decisions
   - codec behavior
2. Contract tests
   - trait implementations
   - adapter conformance
   - provider interchangeability
3. Integration tests
   - multi-crate runtime behavior
   - lifecycle orchestration
   - simulated node interactions
4. Compatibility tests
   - Lokinet-config parsing parity
   - expected behavior for naming, routing, DNS, and service flows
5. Performance and soak tests
   - selected hotspots
   - packet/path/routing benchmarks

### 9.3 Test Ownership

Each implementation task must declare:

- files under change
- tests added
- commands run
- expected pass/fail evidence

## 10. Subagent Cluster Workflow

### 10.1 Roles

`GPT-5.5`

- owns architecture and roadmap
- writes and updates specs/plans
- dispatches implementation tasks
- reviews spec compliance
- performs code-quality review
- decides acceptance or rework

`GPT-5.4` or `GPT-5.3-Codex`

- executes isolated implementation tasks
- follows TDD per task
- reports concerns explicitly

### 10.2 Task Gate

Every task must follow this order:

1. task spec prepared by GPT-5.5
2. implementer subagent writes tests first
3. implementer completes minimal code
4. implementer runs verification
5. GPT-5.5 spec-compliance review
6. GPT-5.5 code-quality review
7. rework if either review fails
8. task marked complete only after both reviews pass

### 10.3 Work Packet Format

Each task handed to an implementer should include:

- exact objective
- affected files
- forbidden shortcuts
- expected tests
- acceptance criteria
- related architecture constraints
- status ledger update requirement

## 11. Resumability and Progress Tracking

This is a mandatory part of the architecture process, not optional documentation.

### 11.1 Required Status Artifacts

The repository must maintain:

- `docs/status/roadmap.md`
- `docs/status/current-phase.md`
- `docs/status/modules/<module-name>.md`
- `docs/status/session-log/YYYY-MM-DD.md`

### 11.2 Required Per-Module Record

Each module status file must include:

- purpose
- public interfaces
- implemented items
- partially implemented items
- not yet implemented items
- known risks
- test coverage state
- compatibility notes
- next recommended tasks
- files and crates involved

### 11.3 Required Per-Session Record

Every meaningful work session must leave a short note covering:

- what changed
- what did not change
- what remains blocked
- what should be done next
- what was verified

This ensures the next session can continue without reconstructing context from scratch.

## 12. Documentation and Decision Records

Architecture changes should be accompanied by lightweight decision records in `docs/decisions/`. Any deviation from Lokinet compatibility should be documented with:

- rationale
- migration effect
- operator impact
- rollback implications

## 13. Initial Acceptance Criteria for the First Implementation Plan

The first implementation plan should be limited to `Phase 0` and the start of `Phase 1`.

It must produce:

1. a Rust workspace with binary name `saferunnet`
2. a directory structure matching this spec
3. a documented dependency policy
4. a test/lint/format baseline
5. a status ledger system for resumable work
6. an initial config crate plus compatibility parsing skeleton
7. an application kernel skeleton with lifecycle tests

It must not yet attempt full protocol parity.

## 14. Risks and Mitigations

### Risk: Upstream behavior is broad and unevenly documented

Mitigation:

- treat Lokinet behavior as a compatibility target, not a copy target
- use reference-driven tests
- capture intentional deviations explicitly

### Risk: Core crate grows into a hidden god object

Mitigation:

- enforce ownership boundaries in plan tasks
- reject shared mutable runtime dumping grounds in review

### Risk: Dependency fragmentation reappears through convenience choices

Mitigation:

- review dependency additions during planning
- prefer internal crates and adapters

### Risk: Sessions lose continuity

Mitigation:

- require status ledgers per module and per session
- make unfinished scope explicit

## 15. Open Decisions Deferred to Planning

These items are intentionally deferred to the implementation plan so that they can be resolved with task-level specificity:

1. exact async runtime selection
2. exact serialization crate policy
3. exact CLI framework choice
4. exact crypto backend shortlist
5. exact interoperability test fixture shape

These are not unknown goals; they are controlled planning decisions.
