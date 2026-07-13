# SaferunNet

**SaferunNet** — Rust rewrite of the [Lokinet](https://github.com/oxen-io/lokinet) LLARP overlay network.

An anonymous, onion-routed overlay network providing `.loki` / `.snode` / `.sfr` DNS resolution and encrypted packet forwarding through a distributed hash table (DHT). Built from scratch in Rust with trait-based module architecture, Ed25519 identity, AES-256-GCM onion encryption, QUIC transport, and full Lokinet wire-format compatibility.

---

## Quick Start

```powershell
# Clone
git clone https://github.com/saferun-ai/saferunnet.git
cd saferunnet

# Build
cargo build --release

# Create config
@"
[router]
nickname = my-node
data-dir = ./data

[network]
keyfile = ./data/identity.key

[logging]
level = info
"@ | Out-File -FilePath saferunnet.ini -Encoding utf8

# Run
.\target\release\saferunnet --config saferunnet.ini --log-level debug
```

---

## Build Targets

| Target | Command | Output |
|--------|---------|--------|
| CLI binary | `cargo build --bin saferunnet --release` | `target/release/saferunnet.exe` |
| Daemon binary | `cargo build --bin saferunnetd --release` | `target/release/saferunnetd.exe` |
| Dynamic library | `cargo build --lib --release` | `target/release/saferunnet.dll` (`.so` / `.dylib`) |
| Static library | `cargo build --lib --release` | `target/release/saferunnet.rlib` |

### Building as a Dynamic Library (`.dll` / `.so` / `.dylib`)

The `saferunnet` crate is configured with `crate-type = ["cdylib", "lib"]`, producing both a C-compatible dynamic library and a Rust static library:

```powershell
# Windows → saferunnet.dll + saferunnet.dll.lib
cargo build --lib --release

# Linux → libsaferunnet.so
cargo build --lib --release

# macOS → libsaferunnet.dylib
cargo build --lib --release
```

The C API is exposed via `saferunnet/src/capi.rs`. Include `saferunnet.h` (generated with `cbindgen`) and link against the import library.

### Building the Daemon (with integration tests)

```powershell
# Build daemon
cargo build --bin saferunnetd --release

# Run daemon integration tests (multi-node, soak)
cargo test -p saferunnetd
```

---

## Configuration

SaferunNet uses a Lokinet-compatible INI format. Minimal config:

```ini
[router]
nickname = my-node
data-dir = ./data

[network]
keyfile = ./data/identity.key

[logging]
level = info
```

Full configuration reference: see `docs/GETTING_STARTED.md`.

---

## Development

```powershell
# Run all tests (478 tests, 0 failures)
cargo test --workspace

# Check formatting
cargo fmt --all --check

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Build everything
cargo build --workspace --release
```

### Test Breakdown

| Crate | Tests | Description |
|-------|:-----:|-------------|
| `saferunnet-core` | 374 | Identity, crypto, config, DHT, DNS, path, router, session, handlers, link, contact, messages, auth, NodeDB, VPN, util |
| `saferunnet-crypto` | 7 | Ed25519 key generation, signing, verification, signed envelopes |
| `saferunnet-transport` | 29 | QUIC transport, link layer, event loop, handshake |
| `saferunnetd` (lib) | 9 | Daemon module tests |
| `saferunnetd` (integration) | 52 | Multi-node DHT bootstrap, onion relay, exit policy, path build, CLI |

---

## Project Structure

```
saferunnet/
├── saferunnet-core/         # Core library: all protocol modules
│   └── src/
│       ├── address/         # IP range mapping
│       ├── auth/            # Auth backends (file, RPC, compound)
│       ├── config/          # Lokinet-compatible INI config parser
│       ├── consensus/       # Reachability testing
│       ├── constants/       # Protocol constants, version
│       ├── contact/         # RouterContact, ClientContact, EncryptedCC, ContactDB
│       ├── dht/             # Kademlia DHT + network layer
│       ├── dns/             # DNS server, resolver chain, message codec
│       ├── encoding/        # BtDict / BtList wire format (oxenc-compatible)
│       ├── handlers/        # TunEndpoint, SessionEndpoint, IP mapping
│       ├── messages/        # Session, DHT, fetch, path message types
│       ├── net/             # Platform TUN, DNS, netif (Windows/macOS/Linux)
│       ├── path/            # Path build, transit hop, path control
│       ├── router/          # Router orchestration, onion encryption, relay
│       ├── rpc/             # JSON-RPC admin server, Oxen client
│       ├── session/         # Session state machine, transport, encryption
│       ├── util/            # Time, buffer, zstd, file, decaying hashmap
│       └── vpn/             # Exit relay, packet router, policy
├── saferunnet-crypto/       # Ed25519 key material, signing, envelopes
├── saferunnet-transport/    # QUIC transport, link layer, UDP, event loop
├── saferunnet-platform/     # Platform-specific TUN device (WinTun)
├── saferunnet-observability/ # Logging, tracing, ring buffer, callbacks
├── saferunnet/              # Lib crate (cdylib + rlib) + CLI binary
│   └── src/
│       ├── main.rs          # CLI entry point (clap)
│       ├── lib.rs           # C API exports + kernel wiring
│       ├── capi.rs          # C-compatible FFI interface
│       └── kernel.rs        # Module wiring and lifecycle
├── apps/saferunnetd/        # Daemon binary with integration tests
└── tests/fixtures/lokinet/  # Lokinet reference configs
```

---

## Status

- **Tests:** 478 passed, 0 failed, 0 ignored
- **Wire format:** Lokinet-compatible bt_dict encoding (RelayContact, ClientContact, EncryptedCC, SRV)
- **Transport:** QUIC via quinn + UDP fallback + TCP tunnel
- **Session encryption:** Ed25519 key exchange + xchacha20-poly1305
- **DHT:** Kademlia with SNS resolution
- **DNS:** Recursive resolver chain + DoH blocking + platform DNS config
- **Auth:** File-based, RPC (Oxen), compound backends
- **Platform:** Windows (WinTun), macOS (utun), Linux (tun)
- **P0/P1/P2 gaps:** All resolved

---


---

## Documentation

### Getting Started
| Document | Description |
|----------|-------------|
| [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) | Prerequisites, build commands, CLI reference, configuration, platform notes, C API usage |

### Architecture & Design
| Document | Description |
|----------|-------------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Architecture overview, crate dependency graph, module composition, data flow, security model |
| [`docs/API.md`](docs/API.md) | Full API reference — types, traits, config format, CLI reference |
| [`docs/architecture/dependency-policy.md`](docs/architecture/dependency-policy.md) | Crate dependency rules and convergence policy |

### Design Specs & Plans
| Document | Description |
|----------|-------------|
| [`docs/superpowers/specs/2026-06-25-saferunnet-rewrite-design.md`](docs/superpowers/specs/2026-06-25-saferunnet-rewrite-design.md) | Original rewrite design spec |
| [`docs/superpowers/specs/2026-06-27-saferunnet-architecture-design.md`](docs/superpowers/specs/2026-06-27-saferunnet-architecture-design.md) | Architecture design decisions |
| [`docs/superpowers/plans/`](docs/superpowers/plans/) | Implementation plans (Phase 0–7) |

### Module Status
| Document | Module |
|----------|--------|
| [`docs/status/modules/app-kernel.md`](docs/status/modules/app-kernel.md) | App kernel — lifecycle, service registry, module orchestration |
| [`docs/status/modules/config-system.md`](docs/status/modules/config-system.md) | Config system — INI parser, validation, normalization |
| [`docs/status/modules/crypto-system.md`](docs/status/modules/crypto-system.md) | Crypto — Ed25519, signed envelopes, key generation |
| [`docs/status/modules/identity-system.md`](docs/status/modules/identity-system.md) | Identity — NodeIdentity, file persistence, proofs |
| [`docs/status/modules/link-system.md`](docs/status/modules/link-system.md) | Link layer — path control, session init/accept/close |
| [`docs/status/modules/router-system.md`](docs/status/modules/router-system.md) | Router — announcements, capabilities, path build |
| [`docs/status/modules/service-system.md`](docs/status/modules/service-system.md) | Service messages — authenticated protocol families |

### Project Status
| Document | Description |
|----------|-------------|
| [`docs/status/roadmap.md`](docs/status/roadmap.md) | Development roadmap (Phase 0–6) |
| [`docs/status/current-phase.md`](docs/status/current-phase.md) | Current phase status and active work |
| [`docs/status/session-log/`](docs/status/session-log/) | Session logs — per-session changelogs and verification |

---

## License

MIT OR Apache-2.0