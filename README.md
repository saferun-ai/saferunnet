# ReburnSaferunNet

`saferunnet` is the Rust rewrite workspace for the Saferunnet/Lokinet effort.

## Current Status

- Phase: Phase 0 complete, early Phase 1 and Phase 2 groundwork in progress
- Spec: `docs/superpowers/specs/2026-06-25-saferunnet-rewrite-design.md`
- Plan: `docs/superpowers/plans/2026-06-25-saferunnet-phase0-phase1-foundation.md`
- Runtime: app kernel, service registry, config normalization, config-driven identity bootstrap, concrete Ed25519 key generation, signed-envelope codecs, identity proofs, authenticated service messages, the first typed router announcement boundary, and the first typed link path-control boundary are available as tested foundations

## Bootstrap Commands

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
