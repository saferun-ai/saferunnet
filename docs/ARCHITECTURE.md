# Saferunnet Architecture

## Project Overview

**Saferunnet** is a from-scratch Rust rewrite of the [Lokinet](https://github.com/oxen-io/lokinet) LLARP (Low-Latency Anonymous Routing Protocol) overlay network. The daemon binary is named `saferunnet`.

It provides:

- A **TUN-based** virtual network interface for transparent `.loki` DNS resolution
- **Onion-routed** packet forwarding through the DHT overlay
- **Ed25519** identity with **AES-256-GCM** onion encryption
- Composition-based module architecture via the `RuntimeModule` trait

## Crate Dependency Graph

```
                    ┌──────────────────┐
                    │   saferunnetd    │  (binary: saferunnet)
                    └────────┬─────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
  ┌──────▼──────┐   ┌───────▼───────┐   ┌───────▼──────┐
  │ saferunnet  │   │ saferunnet    │   │ saferunnet   │
  │   -app      │   │   -config     │   │   -dht       │
  └──────┬──────┘   └───────┬───────┘   └───────┬──────┘
         │                   │                   │
  ┌──────▼──────┐   ┌───────▼───────┐   ┌───────▼──────┐
  │ saferunnet  │   │ saferunnet    │   │ saferunnet   │
  │   -core     │   │ -compat-      │   │   -dns       │
  │             │   │   lokinet     │   │              │
  └──────┬──────┘   └───────────────┘   └───────┬──────┘
         │                                       │
  ┌──────▼──────────────────────────────────────▼──────┐
  │                                                    │
  │  Domain crates:                                     │
  │  ┌────────────┐ ┌────────────┐ ┌────────────┐      │
  │  │ -identity  │ │ -crypto    │ │ -exit      │      │
  │  └────────────┘ └────────────┘ └────────────┘      │
  │  ┌────────────┐ ┌────────────┐ ┌────────────┐      │
  │  │ -transport │ │ -platform  │ │ -router    │      │
  │  └────────────┘ └────────────┘ └────────────┘      │
  │  ┌────────────┐ ┌────────────┐ ┌────────────┐      │
  │  │ -link      │ │ -path      │ │ -service   │      │
  │  └────────────┘ └────────────┘ └────────────┘      │
  │  ┌────────────┐ ┌────────────┐                     │
  │  │ -rpc       │ │ -testing   │                     │
  │  └────────────┘ └────────────┘                     │
  │  ┌──────────────────────┐                          │
  │  │ -observability       │                          │
  │  └──────────────────────┘                          │
  └────────────────────────────────────────────────────┘
```

**Dependency flow:** `saferunnet-core` is the root crate — every domain crate depends on it or is standalone. `saferunnet-app` pulls domain crates together into `RuntimeModule` implementations. `saferunnetd` is the binary entry point that wires modules into the `AppKernel` and runs the event loop.

## Module Composition Pattern

The architecture uses **composition over inheritance**. Every subsystem is a `RuntimeModule` registered with the `AppKernel`.

### RuntimeModule Trait

```rust
pub trait RuntimeModule {
    fn name(&self) -> &'static str;
    fn register_services(&mut self, services: &mut ServiceRegistry) -> Result<(), ModuleError>;
    fn required_service_keys(&self) -> &[ServiceKey];
    fn wire(&mut self, services: &ServiceRegistry) -> Result<(), ModuleError>;
    fn start(&mut self) -> Result<(), ModuleError>;
    fn stop(&mut self) -> Result<(), ModuleError>;
}
```

### AppKernel

The `AppKernel` orchestrates the lifecycle of all modules in three phases:

1. **Register Phase** — Each module registers its services into the `ServiceRegistry` (a type-erased, type-safe DI container). On failure, previously registered modules are rolled back.
2. **Wire Phase** — Modules resolve their dependencies from the `ServiceRegistry` via `required_service_keys()` and `wire()`. Missing services cause a startup error with rollback.
3. **Start Phase** — Each module calls `start()`. On failure, started modules are rolled back.

```rust
let mut kernel = AppKernel::new();
kernel.register(Box::new(IdentityModule::from_runtime_settings(nickname, keyfile)));
kernel.register(Box::new(LinkMessageModule::new()));
kernel.register(Box::new(LinkSessionStateModule::default()));
kernel.register(Box::new(PathManagerModule::new()));
kernel.register(Box::new(DnsResolverModule::new()));
kernel.start().expect("start kernel");
```

### ServiceRegistry

A typed service container backed by `HashMap<TypeId, Box<dyn Any + Send + Sync>>`. Services are registered by name (`ServiceKey`) and retrieved by type. This provides compile-time type safety for inter-module wiring.

```rust
services.insert_named(NODE_IDENTITY_SERVICE_KEY, node_identity);
// Later, in another module:
let identity = services.get_named::<NodeIdentity>(NODE_IDENTITY_SERVICE_KEY);
```

## Data Flow

### TUN Device → DNS Resolution → Onion Forwarding

```
  ┌──────────┐     read()     ┌──────────────┐
  │  TUN     │ ──────────────▶│ run_tun_loop │
  │  Device  │                │              │
  └──────────┘                └──────┬───────┘
                                     │
                     ┌───────────────┼───────────────┐
                     │ DNS (.loki)   │               │ non-DNS traffic
                     ▼               │               ▼
              ┌─────────────┐       │       ┌──────────────┐
              │handle_dns_  │       │       │OnionForwarder│
              │  query()    │       │       │resolve_and_  │
              └──────┬──────┘       │       │  forward()   │
                     │              │       └──────┬───────┘
                     ▼              │              │
              ┌─────────────┐       │       ┌──────▼───────┐
              │   DhtClient │       │       │ PathBuilder  │
              │lookup_intro │       │       │ + PathSelect │
              │   _set()    │       │       └──────┬───────┘
              └──────┬──────┘       │              │
                     │              │       ┌──────▼───────┐
                     ▼              │       │UdpTransport  │
              ┌─────────────┐       │       │  send_to()   │
              │ DNS Response│       │       └──────────────┘
              │  to TUN     │       │
              └─────────────┘       │
```

1. **TUN read**: The `run_tun_loop` reads raw IP packets from the Windows TUN device
2. **DNS dispatch**: If the packet is a DNS query for `.loki`, `handle_dns_query` resolves it via `DhtClient::lookup_intro_set()`, maps the public key to a `10.x.x.x` virtual IP, and writes a DNS A-record response back to the TUN
3. **Onion forwarding**: Non-DNS traffic is encapsulated by `OnionForwarder::resolve_and_forward()` — the destination IP is mapped to an Ed25519 public key, an onion frame is built (AES-256-GCM), and sent via the `UdpTransport`
4. **DHT bootstrap**: On startup, the daemon bootstraps into the DHT overlay using configured bootstrap routers, then participates in routing

## Security Model

| Layer | Mechanism |
|-------|-----------|
| **Node Identity** | Ed25519 key pair stored on disk (`identity.key`). Used for signing link messages and establishing cryptographic identity |
| **Key Generation** | `Ed25519KeyGenerator` creates fresh keys on first run via `IdentityModule` bootstrap |
| **Onion Encryption** | AES-256-GCM (via `aes-gcm` crate) for encrypting forwarded traffic frames |
| **Exit Policy** | `ExitPolicy` trait (`saferunnet-exit`) gatekeeps traffic leaving the overlay — `allows(target: &str, port: u16) -> Result<(), ExitPolicyError>` |
| **Link Messages** | `AuthenticatedLinkMessage` (in `saferunnet-service`) carries signed, verifiable link-layer control messages |
| **Service Auth** | Identity proofs and signed envelopes via `saferunnet-service` authenticate inter-node communication |

## Crate Descriptions

| Crate | Description |
|-------|-------------|
| `saferunnet-core` | Foundation traits (`RuntimeModule`, `ServiceRegistry`, `LifecycleState`) — the kernel of the framework |
| `saferunnet-app` | Module implementations: `AppKernel`, `IdentityModule`, `DnsResolverModule`, `LinkMessageModule`, `LinkSessionStateModule`, `PathManagerModule`, `SessionCoordinatorModule` |
| `saferunnet-config` | INI config parsing, normalization, overlay merging — produces `NormalizedConfig` |
| `saferunnet-compat-lokinet` | Lokinet `.ini` file parser — handles raw section/key/value extraction for backward compatibility |
| `saferunnet-crypto` | Cryptographic primitives: Ed25519 key generation, `PublicKey`/`PrivateKey` types, `KeyAlgorithm` enum |
| `saferunnet-dht` | Distributed Hash Table — `NetworkDht` with bootstrap, peer count, and intro-set queries |
| `saferunnet-dns` | Loki DNS resolver: `DhtClient` trait (query DHT by public key), `LokiResolver` trait for name resolution |
| `saferunnet-exit` | Exit node policy — `ExitPolicy` trait for controlling traffic leaving the overlay |
| `saferunnet-identity` | Node identity management: `NodeIdentity`, `IdentitySpec`, `FileIdentityRepository` (on-disk persistence) |
| `saferunnet-link` | Link-layer primitives: message types, session protocol boundaries (path-control, session-init, session-accept, etc.) |
| `saferunnet-observability` | Tracing/logging setup via `tracing-subscriber` — simple `install(level)` call |
| `saferunnet-path` | Onion path construction: `PathBuilder`, `PathSelector`, `PathHealthChecker` traits with default implementations |
| `saferunnet-platform` | Platform abstraction: `TunDevice` trait, `WinTunDevice` implementation (Windows TUN adapter via `wintun`) |
| `saferunnet-router` | Router-level functionality — router announcements and typed routing boundaries |
| `saferunnet-rpc` | Admin RPC server — exposes node state and peer count over HTTP/JSON |
| `saferunnet-service` | Typed link message codec: `AuthenticatedLinkMessage`, `SessionState`, signed envelopes, identity proofs |
| `saferunnet-testing` | Test utilities and shared test fixtures |
| `saferunnet-transport` | UDP transport layer: `LinkTransport` trait, `UdpTransport` implementation, `Datagram` type |
| `saferunnetd` | Binary crate — produces `saferunnet` executable with daemon, bootstrap, service management, and config check modes |

## Key Design Decisions

1. **Composition over inheritance**: Every feature is a `RuntimeModule` that plugs into the `AppKernel`. No deep class hierarchies — flat trait-based composition.
2. **Trait-based service wiring**: Modules declare dependencies via `required_service_keys()` and resolve them through the `ServiceRegistry`. This enables compile-time type safety with runtime flexibility.
3. **Flat dependency tree**: Domain crates are mostly leaf nodes. Only `saferunnet-core` is a hard dependency of most crates. `saferunnet-app` is the sole integration layer — no crate depends on another domain crate.
4. **INI config compatibility**: The config format mirrors legacy Lokinet `.ini` files for a smooth migration path. `saferunnet-compat-lokinet` parses the raw format; `saferunnet-config` normalizes it into a typed `NormalizedConfig`.
5. **Windows-first TUN**: The initial platform target is Windows. `WinTunDevice` uses the `wintun` driver for TUN adapter creation. Platform abstraction via `TunDevice` trait allows future Linux/macOS support.
6. **Async runtime via Tokio**: `tokio::runtime::Runtime` wrapped in `Arc` provides multi-threaded async execution for DHT bootstrap, RPC serving, and transport I/O.
7. **Gradual rollback on failure**: The `AppKernel` startup sequence rolls back previously started modules if any module fails during registration, wiring, or start — ensuring clean shutdown on error.
