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
- app-kernel integration via a published node-identity runtime service

## Partially Implemented Items

- file repository exists, but only for a simple local text format
- identity bootstrap depends on an injected key generator contract because no concrete crypto backend exists yet

## Not Yet Implemented

- repository migration from Lokinet-native files
- encrypted key storage

## Known Risks

- persisted identity format is intentionally simple and not yet compatible with upstream key files
- runtime publication still depends on a string service key contract inherited from the kernel

## Test Coverage State

- file round-trip is covered
- missing field rejection is covered
- missing-file bootstrap and persistence is covered
- runtime identity publication to dependent modules is covered

## Compatibility Notes

- this is an internal persistence contract, not yet a drop-in replacement for Lokinet key files or native keyfile formats

## Next Recommended Tasks

- implement a concrete key generator behind the existing bootstrap contract
- map the repository to Lokinet-compatible keyfile expectations
- add migration or import paths from upstream identity artifacts

## Files and Crates Involved

- `crates/saferunnet-identity`
