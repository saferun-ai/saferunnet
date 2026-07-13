# Getting Started with SaferunNet

## Prerequisites

- **Rust** stable 1.75+ ([install via rustup](https://rustup.rs))
- **Windows** / **macOS** / **Linux** (TUN device support on all platforms)
- **Git** (to clone the repository)
- **Administrator/root privileges** (required for TUN adapter creation)

## Quick Start

```powershell
# 1. Clone
git clone https://github.com/saferun-ai/saferunnet.git
cd saferunnet

# 2. Build
cargo build --release

# 3. Create config
@"
[router]
nickname = my-node
data-dir = ./data

[network]
keyfile = ./data/identity.key

[logging]
level = info
"@ | Out-File -FilePath saferunnet.ini -Encoding utf8

# 4. Run
.\target\release\saferunnet --config saferunnet.ini
```

## Build Commands

| Command | Description |
|---------|-------------|
| `cargo build --release` | Build all targets (lib + bins) |
| `cargo build --bin saferunnet --release` | CLI binary only → `target/release/saferunnet.exe` |
| `cargo build --bin saferunnetd --release` | Daemon binary only → `target/release/saferunnetd.exe` |
| `cargo build --lib --release` | Library only → `target/release/saferunnet.dll` / `.so` / `.dylib` |
| `cargo check` | Fast compile check (no binary output) |
| `cargo test --workspace` | Run all 478 tests across all crates |
| `cargo test -p saferunnetd` | Run daemon + integration tests |
| `cargo fmt --all --check` | Check code formatting |
| `cargo clippy --workspace --all-targets` | Run linter |

## CLI Reference

```
SaferunNet -- Lokinet-compatible VPN daemon

Usage: saferunnet.exe [OPTIONS]

Options:
  -c, --config <CONFIG>        Path to configuration file [default: saferunnet.ini]
      --nickname <NICKNAME>    Override node nickname
      --keyfile <KEYFILE>      Path to identity key file
      --oxend-url <OXEND_URL>  Oxen daemon JSON-RPC endpoint
      --log-level <LOG_LEVEL>  Log level: trace, debug, info, warn, error
      --log-file <LOG_FILE>    Log to file instead of stdout
  -h, --help                   Print help
  -V, --version                Print version
```

## Configuration (Lokinet-compatible INI)

```ini
[router]
nickname = my-node
data-dir = ./data         # Working directory for identity, DB, logs

[network]
keyfile = ./data/identity.key   # Ed25519 identity key path
bind = 0.0.0.0:1090             # QUIC listen address
ifaddr = 10.0.0.1/16            # TUN interface address
exit = false                     # Enable exit mode
hops = 4                        # Path hop count
paths = 6                       # Active path count
exit-node = <pubkey>            # Exit node pubkey (repeatable)

[logging]
level = info              # trace | debug | info | warn | error
file = saferunnet.log     # Log file path (omit for stdout)
```

## Building as a Dynamic Library

SaferunNet can be embedded as a C-compatible shared library:

```powershell
# Build shared library
cargo build --lib --release

# Windows output:
#   target/release/saferunnet.dll
#   target/release/saferunnet.dll.lib  (import library)
#
# Linux output:
#   target/release/libsaferunnet.so
#
# macOS output:
#   target/release/libsaferunnet.dylib
```

The C API is in `saferunnet/src/capi.rs`. Link against the library and include the generated header:

```c
// Example C usage
#include "saferunnet.h"

int main() {
    saferunnet_config_t cfg = saferunnet_config_default();
    saferunnet_t* ctx = saferunnet_init(&cfg);
    saferunnet_start(ctx);
    // ... use the network ...
    saferunnet_stop(ctx);
    saferunnet_free(ctx);
    return 0;
}
```

## Running Tests

```powershell
# All tests (478 total)
cargo test --workspace

# Specific crate
cargo test -p saferunnet-core
cargo test -p saferunnet-transport
cargo test -p saferunnet-crypto

# Daemon integration tests (requires admin for TUN tests)
cargo test -p saferunnetd

# With output
cargo test -- --nocapture

# Specific test
cargo test -p saferunnet-core -- test_router_id_b32z_roundtrip
```

## Connecting to Oxen Network

To join the live Oxen Service Node network:

```ini
[router]
nickname = my-router

[network]
keyfile = ./identity.key
bind = 0.0.0.0:1090
```

```powershell
# Point to a running oxend instance
.\target\release\saferunnet --config saferunnet.ini --oxend-url http://127.0.0.1:22023/json_rpc
```

Without oxend, SaferunNet starts in standalone mode and will periodically retry the Oxen chain connection.

## Platform Notes

| Platform | TUN Backend | DNS Config | Notes |
|----------|------------|------------|-------|
| Windows | WinTun (wintun.dll) | Registry | Requires admin for TUN creation |
| macOS | utun | scutil | Tested on macOS 12+ |
| Linux | tun | systemd-resolved / NetworkManager | Requires `CAP_NET_ADMIN` or root |
