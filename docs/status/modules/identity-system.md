# Identity System Status

## Purpose

Persist and reload node identity material without leaking file-format concerns into the runtime.

## Public Interfaces

- `NodeIdentity`
- `FileIdentityRepository`
- `IdentitySpec`

## Implemented Items

- identity file save/load round-trip
- algorithm-aware identity parsing
- missing field diagnostics
- load-or-create bootstrap for missing identity files
- bootstrap path validated against the real Ed25519 generator
- app-kernel integration via a published node-identity runtime service
- best-effort secure file creation and replace-on-save flow for identity persistence
- Windows ACL hardening and replace-on-save behavior are exercised in tests

## Partially Implemented Items

- file repository exists, but only for a simple local text format
- identity bootstrap depends on an injected key generator contract, but the first real Ed25519 backend now exists

## Not Yet Implemented

- repository migration from Lokinet-native files
- encrypted key storage

## Known Risks

- persisted identity format is intentionally simple and not yet compatible with upstream key files
- runtime publication still depends on a string service key contract inherited from the kernel
- identity serialization still requires transient in-memory copies because the persisted format is line-oriented text

## Test Coverage State

- file round-trip is covered
- missing field rejection is covered
- missing-file bootstrap and persistence is covered
- missing-file bootstrap with the real Ed25519 backend is covered
- runtime identity publication to dependent modules is covered
- Windows ACL hardening is covered

## Compatibility Notes

- this is an internal persistence contract, not yet a drop-in replacement for Lokinet key files or native keyfile formats

## Next Recommended Tasks

- map the repository to Lokinet-compatible keyfile expectations
- add migration or import paths from upstream identity artifacts
- wire config-derived keyfile paths into the runtime bootstrap path
- reduce transient secret copies further when the persisted identity format is redesigned

## Files and Crates Involved

- `crates/saferunnet-identity`
