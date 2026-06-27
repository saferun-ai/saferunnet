# Saferunnet

**Saferunnet** — Rust rewrite of the Lokinet LLARP overlay network.

An anonymous, onion-routed overlay network providing `.loki` DNS resolution and encrypted
packet forwarding through a distributed hash table (DHT). Built from scratch in Rust with
a composition-based module architecture, Ed25519 identity, and AES-256-GCM onion encryption.

## Quick Start

```powershell
# Build
cargo build --release

# Create minimal config
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

# Bootstrap identity, then run
.\target\release\saferunnet --bootstrap saferunnet.ini
.\target\release\saferunnet daemon --config saferunnet.ini
```

## Current Status

- **Phase:** Phase 0 complete, early Phase 1 and Phase 2 groundwork in progress
- **Spec:** `docs/superpowers/specs/2026-06-25-saferunnet-rewrite-design.md`
- **Plan:** `docs/superpowers/plans/2026-06-25-saferunnet-phase0-phase1-foundation.md`
- **Runtime:** App kernel, service registry, config normalization, config-driven identity bootstrap, Ed25519 key generation, signed-envelope codecs, identity proofs, authenticated service messages, typed router announcements, typed link path-control/session-init/session-accept/session-path-switch/session-close boundaries, and unified typed link-message decode/dispatch boundary

## Documentation

| Document | Description |
|----------|-------------|
| `docs/ARCHITECTURE.md` | Architecture overview, crate dependency graph, module composition, data flow, security model |
| `docs/API.md` | Full API reference — 18 crates with key types, config format, trait signatures, CLI reference |
| `docs/GETTING_STARTED.md` | Developer guide — prerequisites, build, test, config, running, Windows service management |

## Development

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
```

## License

MIT OR Apache-2.0
