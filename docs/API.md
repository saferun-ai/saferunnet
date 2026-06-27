# Saferunnet API Reference

## Crate Listing with Key Types

### saferunnet-core
Foundation traits and service infrastructure.

| Type | Kind | Description |
|------|------|-------------|
| `RuntimeModule` | Trait | Module lifecycle: `name()`, `register_services()`, `required_service_keys()`, `wire()`, `start()`, `stop()` |
| `ServiceRegistry` | Struct | Type-erased DI container: `insert()`, `insert_named()`, `get()`, `get_named()`, `contains_key()`, `clear_registrations()` |
| `ServiceKey` | Struct | Typed service identifier: `of::<T>(name)`, `name()` |
| `LifecycleState` | Enum | `Created`, `Starting`, `Running`, `Stopping`, `Stopped` |
| `ModuleError` | Enum (Error) | `Lifecycle`, `ServiceRegistration`, `Wiring`, `Startup`, `Shutdown` |
| `RuntimeHandle` | Type Alias | `Arc<tokio::runtime::Runtime>` |

### saferunnet-app
Module implementations that compose domain crates into `RuntimeModule` instances.

| Type | Kind | Description |
|------|------|-------------|
| `AppKernel` | Struct | Module lifecycle orchestrator: `new()`, `register()`, `start()`, `stop()`, `services()`, `runtime()` |
| `IdentityModule` | Struct | Node identity bootstrap: `new()`, `from_runtime_settings(nickname, keyfile)` |
| `DnsResolverModule` | Struct | DNS resolver registration: `new()`, `with_resolver()` |
| `LinkMessageModule` | Struct | Link message dispatcher registration |
| `LinkSessionStateModule` | Struct | Shared `SessionState` registration: `new()`, `from_shared_state()` |
| `LinkMessageDispatcher` | Struct | Link message decode: `decode_verified()`, `decode_unverified()`, `decode()` |
| `PathManagerModule` | Struct | Path service registration: `new()`, `with_router_pool()` |
| `SessionCoordinatorModule` | Struct | Session lifecycle coordinator: `new()`, `dispatcher()`, `session_state()`, `is_started()` |
| `SharedLokiResolver` | Type Alias | `Arc<Mutex<dyn LokiResolver + Send>>` |
| `SharedPathSelector` | Type Alias | `Arc<Mutex<dyn PathSelector + Send>>` |
| `SharedPathBuilder` | Type Alias | `Arc<Mutex<dyn PathBuilder + Send>>` |
| `SharedPathHealthChecker` | Type Alias | `Arc<Mutex<dyn PathHealthChecker + Send>>` |
| `LinkSessionState` | Type Alias | `Arc<Mutex<SessionState>>` |

### saferunnet-config
INI configuration loading and normalization.

| Type | Kind | Description |
|------|------|-------------|
| `NormalizedConfig` | Struct | Typed config: `router: RouterConfig`, `logging: LoggingConfig`, `network: NetworkConfig` |
| `RouterConfig` | Struct | `nickname: String`, `data_dir: String`, `bind_port: u16`, `rpc_port: u16` |
| `NetworkConfig` | Struct | `bootstrap_routers: Vec<String>`, `exit: bool`, `reachable: bool`, `keyfile: Option<String>`, `ifaddr: Option<String>`, `exit_nodes: Vec<String>`, `hops: Option<u8>`, `paths: Option<u8>` |
| `LoggingConfig` | Struct | `level: String` |
| `ConfigError` | Enum (Error) | `ReadConfig`, `Parse`, `MissingRouterSection`, `InvalidValue`, `ReadConfigDir` |
| `load_from_path()` | Function | Load config from file path with `.d` overlay directory merging |
| `load_from_file()` | Function | Load config from a single file without overlay |
| `load_from_str()` | Function | Parse config from a string |

### saferunnet-compat-lokinet
Lokinet `.ini` format parser.

| Type | Kind | Description |
|------|------|-------------|
| `RawLokinetConfig` | Struct | Raw section-key-values mapping |
| `parse()` | Function | Parse INI string into `RawLokinetConfig` |
| `ParseError` | Enum (Error) | Parse failure details |

### saferunnet-crypto
Cryptographic primitives.

| Type | Kind | Description |
|------|------|-------------|
| `KeyAlgorithm` | Enum | `Ed25519` |
| `PublicKey` | Struct | Ed25519 public key: `to_bytes()`, `from_bytes(algorithm, bytes)` |
| `PrivateKey` | Struct | Ed25519 private key |
| `KeyGenerator` | Trait | `generate() -> Result<(PublicKey, PrivateKey), ...>` |
| `Ed25519KeyGenerator` | Struct | Concrete Ed25519 key generation |
| `KeyPair` | Struct | Combined public + private key |

### saferunnet-dht
Distributed Hash Table.

| Type | Kind | Description |
|------|------|-------------|
| `NetworkDht` | Struct | DHT node: `new(key, transport, bootstrap_addrs)`, `bootstrap()`, `peer_count()` |

### saferunnet-dns
Loki DNS resolution.

| Type | Kind | Description |
|------|------|-------------|
| `DhtClient` | Trait | DHT query interface: `lookup_intro_set(target: &PublicKey) -> Vec<DhtIntroResult>` |
| `DhtIntroResult` | Struct | Intro set result: `public_key: PublicKey`, `addresses: Vec<String>` |
| `LokiResolver` | Trait | Name resolver: `resolve(name: &str) -> Result<Vec<PublicKey>, DnsError>` |
| `DnsError` | Enum (Error) | `NotLokiName`, resolution failures |
| `is_loki_name()` | Function | Check if a name ends with `.loki` |

### saferunnet-exit
Exit policy enforcement.

| Type | Kind | Description |
|------|------|-------------|
| `ExitPolicy` | Trait | `allows(target: &str, port: u16) -> Result<(), ExitPolicyError>` |
| `ExitPolicyError` | Enum (Error) | Policy violation details |

### saferunnet-identity
Node identity persistence.

| Type | Kind | Description |
|------|------|-------------|
| `NodeIdentity` | Struct | Node identity with Ed25519 keys and nickname |
| `IdentitySpec` | Struct | `nickname: String`, `algorithm: KeyAlgorithm` |
| `FileIdentityRepository` | Struct | On-disk identity storage: `new(keyfile)`, `load_or_create(spec, generator)` |

### saferunnet-link
Link-layer protocol messages.

| Type | Kind | Description |
|------|------|-------------|
| Link message types for path-control, session-init, session-accept, session-path-switch, session-close boundaries |

### saferunnet-observability
Logging and tracing.

| Type | Kind | Description |
|------|------|-------------|
| `install()` | Function | Initialize tracing subscriber with env-filter: `install(level: &str)` |

### saferunnet-path
Onion path construction and selection.

| Type | Kind | Description |
|------|------|-------------|
| `PathBuilder` | Trait | Build onion paths through the DHT |
| `PathSelector` | Trait | Select best available path |
| `PathHealthChecker` | Trait | Monitor path liveness |
| `RandomPathBuilder` | Struct | Random path construction: `new(router_pool)` |
| `FirstAvailableSelector` | Struct | Simple first-available selection |
| `PingHealthChecker` | Struct | Ping-based health checking |

### saferunnet-platform
Platform abstraction (Windows TUN).

| Type | Kind | Description |
|------|------|-------------|
| `TunDevice` | Trait | `read(buf) -> Result<usize, TunError>`, `write(buf) -> Result<usize, TunError>`, `mtu() -> usize` |
| `WinTunDevice` | Struct | Windows TUN adapter: `create(name, ip, mtu)` |
| `TunError` | Enum (Error) | TUN I/O errors |

### saferunnet-router
Router-level functionality.

| Type | Kind | Description |
|------|------|-------------|
| Router announcement types and typed routing boundaries |

### saferunnet-rpc
Admin RPC server.

| Type | Kind | Description |
|------|------|-------------|
| `RpcServer` | Struct | HTTP admin server: `new(addr)`, `with_node_state(fn)`, `with_peer_count(fn)`, `serve()` |

### saferunnet-service
Typed link message codec.

| Type | Kind | Description |
|------|------|-------------|
| `AuthenticatedLinkMessage` | Struct | Signed link message: `decode()`, `decode_verified()`, `decode_unverified()` |
| `SessionState` | Struct | Active session tracking: `new()` |
| `LinkMessageError` | Enum (Error) | Decode/verify failures |

### saferunnet-testing
Test utilities and shared fixtures.

### saferunnet-transport
UDP transport layer.

| Type | Kind | Description |
|------|------|-------------|
| `LinkTransport` | Trait | `local_addr()`, `send_to(data, addr)`, `recv_from(buf)`, `close()` |
| `UdpTransport` | Struct | UDP socket transport: `bind(addr)` |
| `Datagram` | Struct | Received datagram: data + source address |
| `TransportError` | Enum (Error) | Transport I/O errors |

### saferunnetd
Binary crate producing the `saferunnet` executable.

---

## Configuration Format Reference

Saferunnet uses Lokinet-compatible `.ini` files. Configuration is loaded from a base file
with optional `.d` directory overlays (files merged in sorted order).

### Sections

#### `[router]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `nickname` | string | `saferunnet-node` | Human-readable node name |
| `data_dir` | path | `./var/lib/saferunnet` | Data directory for identity and state |
| `bind_port` | u16 | `1090` | UDP port for link-layer transport |
| `rpc_port` | u16 | `1190` | TCP port for admin RPC |
| `bootstrap` | comma-separated list | (none) | Bootstrap router addresses (`pubkey@host:port`) |

#### `[network]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `exit` | bool | `false` | Enable exit node mode |
| `reachable` | bool | `false` | Node is publicly reachable |
| `keyfile` | path | (none) | Path to identity key file (relative to data_dir) |
| `ifaddr` | CIDR | (none) | TUN interface address (e.g., `10.0.0.1/16`). Required when `exit=true` |
| `exit-node` | multi-value | (none) | Exit node addresses |
| `hops` | u8 (>0) | (none) | Number of onion hops per path |
| `paths` | u8 (>0) | (none) | Number of parallel paths |

#### `[logging]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | string | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |

### Example Configuration

```ini
[router]
nickname = my-saferunnet-node
data_dir = ./var/lib/saferunnet
bind_port = 1090
rpc_port = 1190
bootstrap = pubkey1@10.0.0.1:1090,pubkey2@10.0.0.2:1090

[network]
exit = false
reachable = false
ifaddr = 10.0.0.1/16
keyfile = identity.key
hops = 3
paths = 2

[logging]
level = info
```

---

## Key Traits

### `RuntimeModule` (saferunnet-core)

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

### `TunDevice` (saferunnet-platform)

```rust
pub trait TunDevice {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError>;
    fn write(&mut self, buf: &[u8]) -> Result<usize, TunError>;
    fn mtu(&self) -> usize;
}
```

### `ExitPolicy` (saferunnet-exit)

```rust
pub trait ExitPolicy {
    fn allows(&self, target: &str, port: u16) -> Result<(), ExitPolicyError>;
}
```

### `DhtClient` (saferunnet-dns)

```rust
pub trait DhtClient: Send + Sync {
    fn lookup_intro_set(&self, target: &PublicKey) -> Vec<DhtIntroResult>;
}
```

### `LinkTransport` (saferunnet-transport)

```rust
pub trait LinkTransport: Send + Sync {
    fn local_addr(&self) -> SocketAddr;
    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize, TransportError>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<Datagram, TransportError>;
    fn close(&self);
}
```

---

## Daemon CLI Reference

Binary: `saferunnet`

### Subcommands and Flags

| Command / Flag | Arguments | Description |
|----------------|-----------|-------------|
| `daemon --config <FILE>` | `--config <FILE>` | Run as daemon. If `--config` is omitted, the first positional arg is used as config path |
| `daemon <FILE>` | `<FILE>` | Run as daemon with positional config path |
| `--bootstrap <FILE>` | `<FILE>` | Bootstrap node identity: generate keys from config, verify identity service |
| `--check-config <FILE>` | `<FILE>` | Parse and validate config file, print "config ok" on success |
| `--check-services` | (none) | Smoke-test all kernel modules (identity, link, path, DNS, session) |
| `--service-install [CONFIG]` | `[CONFIG]` | (Windows) Register saferunnet as a Windows service via `sc.exe create` |
| `--service-uninstall` | (none) | (Windows) Remove the saferunnet Windows service via `sc.exe delete` |
| `--service-status` | (none) | (Windows) Query saferunnet Windows service status via `sc.exe query` |
| `--update-check [HOST]` | `[HOST]` | Check for available updates; prints version info |
| `--update-apply [HOST]` | `[HOST]` | Download and apply available update |

### Windows Service Details

The service is installed with:
- **Name:** `saferunnet`
- **Display name:** `Saferunnet LLARP Service`
- **Start type:** `auto`
- **Binary path:** `<exe_path> daemon --config <config_path>`

### Build Features

| Feature | Description |
|---------|-------------|
| `soak` | Enable soak testing mode (available on `saferunnetd`) |

**Test with soak:**
```
cargo test -p saferunnetd --features soak
```
