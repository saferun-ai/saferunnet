# Getting Started with Saferunnet

## Prerequisites

- **Rust** stable 1.75+ ([install via rustup](https://rustup.rs))
- **Windows** (for TUN device support — the initial target platform)
- **Git** (to clone the repository)
- **Administrator privileges** (required for TUN adapter creation and Windows service installation)

## Quick Start

```powershell
# 1. Clone the repository
git clone <repository-url> ReburnSaferunNet
cd ReburnSaferunNet

# 2. Build the release binary
cargo build --release

# 3. Create a minimal config
@"
[router]
nickname = my-node
bind_port = 1090
rpc_port = 1190

[network]
ifaddr = 10.0.0.1/16
keyfile = identity.key

[logging]
level = info
"@ | Out-File -FilePath saferunnet.ini -Encoding utf8

# 4. Bootstrap identity
.\target\release\saferunnet --bootstrap saferunnet.ini

# 5. Run the daemon
.\target\release\saferunnet daemon --config saferunnet.ini
```

## Build Commands

| Command | Description |
|---------|-------------|
| `cargo build --release` | Build optimized binary (`target/release/saferunnet.exe`) |
| `cargo build` | Build debug binary (faster compilation, slower runtime) |
| `cargo check` | Fast compile check without producing a binary |
| `cargo test --workspace` | Run all tests across all crates |
| `cargo test -p saferunnetd --features soak` | Run daemon tests with soak feature enabled |
| `cargo fmt --all` | Format all code |
| `cargo clippy --workspace --all-targets -- -D warnings` | Run clippy lints |

## Minimal Configuration

Save as `saferunnet.ini`:

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

### Config Sections

- **`[router]`** — Node nickname, data directory, bind and RPC ports, bootstrap routers
- **`[network]`** — Exit mode, TUN address, onion hop/path counts, key file
- **`[logging]`** — Log level (`trace`, `debug`, `info`, `warn`, `error`)

All config keys have sensible defaults. The only required section is `[router]`.

## Running Saferunnet

### Daemon Mode

```powershell
# With explicit --config flag
saferunnet daemon --config saferunnet.ini

# With positional config path
saferunnet daemon saferunnet.ini
```

The daemon starts the AppKernel, bootstraps the DHT, creates the TUN device (if `ifaddr` is configured), and starts the admin RPC server on `127.0.0.1:<rpc_port>`. Press `Ctrl+C` to gracefully shut down.

### Bootstrap Mode

```powershell
saferunnet --bootstrap saferunnet.ini
```

Generates an Ed25519 identity key (if one does not exist), stores it in `identity.key`, and verifies the identity service. Prints `identity bootstrap ok` on success.

### Config Validation

```powershell
saferunnet --check-config saferunnet.ini
```

Parses and validates the config file. Prints `config ok` on success, or an error message describing the problem.

### Service Smoke Test

```powershell
saferunnet --check-services
```

Creates a temporary identity, starts all kernel modules (identity, link message, link session, path manager, DNS resolver, session coordinator), and verifies they initialize cleanly.

## Windows Service Management

### Install as a Windows Service

```powershell
# Uses the current exe path and specified config
saferunnet --service-install saferunnet.ini

# With default config path (saferunnet.ini)
saferunnet --service-install
```

This registers the binary as a Windows service named `saferunnet` (display name: "Saferunnet LLARP Service") with auto-start. The service runs `saferunnet daemon --config <config_path>`.

### Manage the Service

```powershell
# Check service status
saferunnet --service-status

# Uninstall the service
saferunnet --service-uninstall
```

For manual control, use `sc.exe` directly:

```powershell
sc.exe start saferunnet
sc.exe stop saferunnet
sc.exe query saferunnet
```

## Update Management

```powershell
# Check for available updates
saferunnet --update-check

# Check against a specific update host
saferunnet --update-check https://updates.example.com

# Download and apply an update
saferunnet --update-apply

# Download from a specific host
saferunnet --update-apply https://updates.example.com
```

## CLI Flags Reference

| Flag | Args | Description |
|------|------|-------------|
| `daemon` | `--config <FILE>` or `<FILE>` | Run as daemon |
| `--bootstrap` | `<FILE>` | Bootstrap node identity |
| `--check-config` | `<FILE>` | Validate config file |
| `--check-services` | (none) | Smoke-test kernel modules |
| `--service-install` | `[CONFIG_PATH]` | Windows: install as service |
| `--service-uninstall` | (none) | Windows: uninstall service |
| `--service-status` | (none) | Windows: query service status |
| `--update-check` | `[HOST]` | Check for updates |
| `--update-apply` | `[HOST]` | Download and apply update |

## Project Structure

```
ReburnSaferunNet/
├── apps/
│   └── saferunnetd/          # Binary crate (produces saferunnet.exe)
├── crates/
│   ├── saferunnet-core/      # Foundation traits and service registry
│   ├── saferunnet-app/       # Module implementations (AppKernel)
│   ├── saferunnet-config/    # Config loading and normalization
│   ├── saferunnet-compat-lokinet/  # Lokinet .ini parser
│   ├── saferunnet-crypto/    # Ed25519, AES-256-GCM
│   ├── saferunnet-dht/       # Distributed Hash Table
│   ├── saferunnet-dns/       # Loki DNS resolver
│   ├── saferunnet-exit/      # Exit policy
│   ├── saferunnet-identity/  # Node identity persistence
│   ├── saferunnet-link/      # Link-layer protocol
│   ├── saferunnet-observability/  # Tracing/logging
│   ├── saferunnet-path/      # Onion path construction
│   ├── saferunnet-platform/  # Windows TUN device
│   ├── saferunnet-router/    # Router functionality
│   ├── saferunnet-rpc/       # Admin RPC server
│   ├── saferunnet-service/   # Link message codec
│   ├── saferunnet-testing/   # Test utilities
│   └── saferunnet-transport/ # UDP transport
├── docs/
│   ├── ARCHITECTURE.md       # Architecture overview
│   ├── API.md                # API reference
│   └── GETTING_STARTED.md    # This document
├── tests/                    # Integration tests
├── scripts/                  # Build and utility scripts
└── Cargo.toml                # Workspace manifest
```

## Development Workflow

```powershell
# 1. Format and lint before committing
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings

# 2. Run all tests
cargo test --workspace

# 3. Build release for testing
cargo build --release

# 4. Run a specific crate's tests
cargo test -p saferunnet-config
cargo test -p saferunnetd

# 5. Run with verbose output
RUST_LOG=debug saferunnet daemon --config saferunnet.ini
```

## Troubleshooting

### "failed to create TUN device"
- Ensure you are running as Administrator
- The TUN device requires the `wintun` driver to be available
- Check that `network.ifaddr` is set to a valid CIDR like `10.0.0.1/16`

### "TUN device not supported on this platform"
- TUN support is currently Windows-only via `WinTunDevice`
- Non-Windows platforms will see this info message; the daemon will continue without TUN

### "missing required router section"
- Your config file must have a `[router]` section
- At minimum, `[router]` can be empty (all values have defaults)

### Config validation
Use `--check-config` to validate your config file before running the daemon:
```powershell
saferunnet --check-config saferunnet.ini
```

## Next Steps

- Read `docs/ARCHITECTURE.md` for the system design and crate dependency graph
- Read `docs/API.md` for the full API reference and trait documentation
- See `docs/superpowers/specs/` for the design spec and phase planning
