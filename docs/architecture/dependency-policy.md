# Dependency Policy

## Rules

1. Prefer the standard library before adding crates.
2. Prefer one mature crate over several narrowly overlapping crates.
3. Prefer an internal workspace crate when a third-party option would fragment ownership.
4. Any new dependency must explain why an internal implementation is worse.
5. Parser, protocol, and compatibility glue should stay project-owned where practical.

## Approved Foundation Dependencies

- `thiserror`
- `tracing`
- `tracing-subscriber`
- `ed25519-dalek`
- `rand_core`
- `zeroize`

## Approved Extension Decisions

### Ed25519 backend

- `ed25519-dalek` is approved as the first concrete Ed25519 backend because it covers key generation, signing, verification, and byte conversion in one mature crate instead of forcing us to assemble several smaller cryptography crates.
- `rand_core` is approved alongside it so we can use OS-backed CSPRNG input without pulling the broader `rand` convenience surface into the runtime crates.
- `zeroize` is approved so project-owned secret wrappers can zero memory on drop instead of relying only on backend-internal hygiene.
- `windows-sys` is approved only inside `saferunnet-identity` for Windows-specific ACL hardening and atomic replace operations; no cross-platform runtime crate should depend on it casually.
- The rest of the workspace must continue programming against `saferunnet-crypto` contracts such as `KeyGenerator`, `PublicKey`, and `SecretKey`; no other crate should depend directly on `ed25519-dalek` unless there is an explicit architecture decision.

## Deferred Decisions

- async runtime
- CLI framework
- serialization framework
- signature contract surface
