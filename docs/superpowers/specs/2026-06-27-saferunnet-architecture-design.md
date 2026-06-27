# SaferunNet Architecture Design

**Date**: 2026-06-27
**Status**: Approved
**Source**: Cross-referenced Lokinet C++ (llarp/) at `D:\Projects\CppProjects\Lokinet_Analysis\lokinet`

---

## 1. Motivation

Lokinet (C++ LLARP) depends on fragmented submodules (oxen-libquic, oxen-mq, oxen-encoding, nlohmann, etc.) that make maintenance difficult. This design defines a complete Rust rewrite — **SaferunNet** — with a principled architecture: fewer crates, QUIC-native transport, Oxen chain integration, and full observability.

## 2. Design Principles

1. **对变化编程** — Traits at true variation points (transport, platform, log sink), not arbitrary file splits
2. **扁平化继承** — Trait-based polymorphism, no deep class hierarchies. Composition over inheritance
3. **共享上下文不拆** — Modules that share protocol context (router↔path↔dns↔session) live in one crate
4. **可复用才独立** — Only truly reusable, dependency-free modules become separate crates
5. **每模块必测试** — Every module ships with unit + integration tests

## 3. Target Crate Structure (6 crates)

```
ReburnSaferunNet/
├── saferunnet/               # Binary: CLI entry + main.rs + integration tests
├── saferunnet-core/          # Core: router, path, dns, session, config, handlers,
│   ├── src/                  #        net, auth, consensus, contact, rpc, vpn, dht
│   │   ├── router/
│   │   ├── path/
│   │   ├── dns/
│   │   ├── session/
│   │   ├── config/
│   │   ├── handlers/         # NEW: TunEndpoint, TunBase
│   │   ├── net/              # NEW: IPPacket, checksum, policy
│   │   ├── auth/             # NEW: Auth tokens, session auth
│   │   ├── consensus/        # NEW: Reachability testing
│   │   ├── contact/          # NEW: RouterContact, introset
│   │   ├── rpc/              # ENHANCED: OxenRpcClient
│   │   ├── vpn/
│   │   ├── dht/
│   │   ├── address/          # NEW: IP addressing utils
│   │   ├── constants/        # NEW: Protocol constants
│   │   └── encoding/         # NEW: Bencode (oxen-encoding port)
│   └── tests/
├── saferunnet-crypto/        # Crypto: x25519, ed25519, encryption
├── saferunnet-transport/     # Transport: QUIC (quinn), link layer, event loop
│   ├── src/
│   │   ├── quic.rs           # Quinn wrapper: Connection, Datagrams, Stream
│   │   ├── link.rs           # LinkManager (merged from saferunnet-link)
│   │   ├── event.rs          # Event loop abstraction
│   │   └── tcp_tunnel.rs     # TCPHandle, TCPConnection
│   └── tests/
├── saferunnet-platform/      # Platform: TUN, WinDivert, OS abstraction
└── saferunnet-observability/ # Logging: multi-sink, categories, ring buffer
```

### Merge Map

| Old Crate | → | New Crate |
|---|---|---|
| saferunnet-core, saferunnet-router, saferunnet-path, saferunnet-dns, saferunnet-session, saferunnet-dht, saferunnet-exit, saferunnet-service, saferunnet-config, saferunnet-identity, saferunnet-rpc, saferunnet-compat-lokinet | → | saferunnet-core |
| saferunnet-transport, saferunnet-link | → | saferunnet-transport |
| saferunnet-platform | → | saferunnet-platform |
| saferunnet-crypto | → | saferunnet-crypto |
| saferunnet-observability | → | saferunnet-observability |
| saferunnet-app, saferunnet-testing | → | saferunnet (binary) |

## 4. Transport Layer: QUIC (not raw UDP)

Lokinet C++ evidence (`llarp/link/connection.hpp`):
```cpp
struct Connection {
    std::shared_ptr<quic::Connection> conn;
    std::shared_ptr<quic::Datagrams> datagrams;         // RFC 9221
    std::shared_ptr<quic::BTRequestStream> control_stream;
};
```

**Target**: Replace `saferunnet-transport/udp.rs` with:

```
saferunnet-transport/
├── quic.rs         quinn::Endpoint → quic::Connection wrapper
├── datagrams.rs    QUIC unreliable datagram (RFC 9221)
├── control.rs      Bidirectional stream for link control messages
├── link.rs         LinkManager: connect, send_data_message, send_control_message
├── event.rs        Event loop trait (tokio runtime)
├── tcp_tunnel.rs   TCP-over-QUIC tunnel (QUICTunnel, TCPHandle, TCPConnection)
└── traits.rs       TransportLayer trait for unit testing
```

Dependency: `quinn` + `tokio` (already in project).

## 5. Node Discovery: Oxen Chain RPC

Lokinet C++ evidence (`llarp/rpc/rpc_client.hpp`):
```cpp
class RPCClient {
    oxenmq::OxenMQ& _omq;
    void update_service_node_list();       // fetch from oxend
    void handle_new_service_node_list();   // process JSON
    Ed25519SecretKey obtain_identity_key();
};
```

**Target** (`saferunnet-core/src/rpc/oxen_client.rs`):
- Connect to oxend via ZMQ request/reply
- Call `get_service_nodes` RPC, parse JSON response
- Feed service node list into NodeDB
- Bootstrap fallback: config file bootstrap nodes

Dependency: `zmq.rs` or direct ZMQ bindings.

## 6. Observability: Full Logging System

Lokinet C++ evidence (`llarp/util/logging/`):
- `callback_sink.hpp` — spdlog::sinks::base_sink with callback
- `buffer.hpp` — ring buffer for RPC log push
- `Router::init_logging()` — Print/File/System sinks + category levels

**Target** (`saferunnet-observability/`):
```
src/
├── sink.rs        Print / File / System syslog sinks
├── category.rs    Per-module log level (router=debug, crypto=warn)
├── ringbuf.rs     RingBuffer for RPC log subscription
├── callback.rs    CallbackSink for external consumers
├── config.rs      LoggingConfig from config file
└── init.rs        init_logging(config) → multi-sink setup
```

Base: `tracing` + `tracing-subscriber` (already in project). Add ring buffer and category support.

## 7. New Modules (from Lokinet C++)

| Module | Source | Purpose |
|---|---|---|
| `handlers/` | `llarp/handlers/tun.hpp` | TunEndpoint: inbound/outbound IP packet processing |
| `net/` | `llarp/net/ip_packet.hpp` | IPPacket build/parse, IPv4/IPv6 checksum, net policy |
| `auth/` | `llarp/auth/` | Service node auth tokens, file auth, RPC auth |
| `consensus/` | `llarp/consensus/` | SN reachability testing, failing node tracking |
| `contact/` | `llarp/contact/` | RouterContact struct, introset data |
| `encoding/` | oxen-encoding submodule | Bencode serialization (bt_dict/bt_list/bt_value) |
| `address/` | `llarp/address/` | IP addressing utilities |
| `constants/` | `llarp/constants/` | Global protocol constants |

## 8. External Dependencies

| Lokinet Submodule | Rust Replacement | Priority |
|---|---|---|
| oxen-libquic | `quinn` | P0 |
| oxen-mq | `zmq.rs` or custom ZMQ client | P0 |
| oxen-encoding | Custom bencode (in-core) | P0 |
| nlohmann/json | `serde` + `serde_json` (already) | Done |
| CLI11 | `clap` (already) | Done |
| sqlite_orm | `rusqlite` | Optional |
| pybind11 | `pyo3` | Optional |

## 9. Binary Output

- Name: `saferunnet` (Windows: `saferunnet.exe`)
- Entry point: `saferunnet/src/main.rs`
- CLI: `clap` derive API
- Config: TOML format, compatible with lokinet.ini semantics but improved

## 10. Quality Gates

Every PR must pass:
```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo build --release  # produces saferunnet.exe
```

## 11. Subagent Workflow

Per user requirement:
- **GPT-5.5** (or strongest available) → Overall planning + Code Review
- **GPT-5.4 / GPT-5.3-Codex** → Implementation coding
- **Code Review Gate**: After each subagent completes, GPT-5.5 reviews. If fails, returns review comments for rework.

## 12. Phase Order

| Phase | Content | Dependencies |
|---|---|---|
| **Phase 0** | Crate merge (18→6), cleanup workspace Cargo.toml | None |
| **Phase 1** | Transport rewrite (UDP→QUIC) + event loop | Phase 0 |
| **Phase 2** | Observability rewrite (full logging system) | Phase 0 |
| **Phase 3** | Core new modules: handlers, net, auth, consensus, contact, encoding | Phase 1, 2 |
| **Phase 4** | Oxen chain RPC client (node discovery) | Phase 1 |
| **Phase 5** | Integration: wire all modules, end-to-end tests | Phase 3, 4 |
| **Phase 6** | Polish: Windows service, installer, docs | Phase 5 |
