# ReburnSaferunNet

`saferunnet` is the Rust rewrite workspace for the Saferunnet/Lokinet effort.

## Current Status

- Phase: Foundation bootstrap
- Spec: `docs/superpowers/specs/2026-06-25-saferunnet-rewrite-design.md`
- Plan: `docs/superpowers/plans/2026-06-25-saferunnet-phase0-phase1-foundation.md`

## Bootstrap Commands

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
