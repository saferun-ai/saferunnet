# Identity System Status

## Purpose

Persist and reload node identity material without leaking file-format concerns into the runtime.

## Public Interfaces

- `NodeIdentity`
- `FileIdentityRepository`
- `IdentitySpec`
- `IdentityClaim`
- `IdentityProof`
- `IdentityProofError`

## Implemented Items

- identity file save/load round-trip
- algorithm-aware identity parsing
- missing field diagnostics
- load-or-create bootstrap for missing identity files
- bootstrap path validated against the real Ed25519 generator
- app-kernel integration via a published node-identity runtime service
- best-effort secure file creation and replace-on-save flow for identity persistence
- Windows ACL hardening and replace-on-save behavior are exercised in tests
- daemon bootstrap now resolves config-derived relative keyfile paths and default identity locations before constructing the runtime module
- project-owned identity-proof signing, encoding, decoding, and verification
- verified decode path for encoded identity proofs

## Partially Implemented Items

- file repository exists, but only for a simple local text format
- identity bootstrap depends on an injected key generator contract, but the first real Ed25519 backend now exists
- proof claim encoding currently serves only the first internal identity-proof contract

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
- CLI bootstrap coverage verifies relative keyfile resolution and default keyfile creation under resolved data directories
- identity-proof sign/verify round-trip is covered
- identity-proof encode/decode round-trip is covered
- identity-proof malformed claim decode rejection is covered
- identity-proof mismatched keypair rejection is covered
- identity-proof mismatched claimed signer rejection is covered
- identity-proof verified decode path is covered

## Compatibility Notes

- this is an internal persistence contract, not yet a drop-in replacement for Lokinet key files or native keyfile formats
- identity proofs are now project-owned protocol foundations and not yet a Lokinet wire-format compatibility layer

## Next Recommended Tasks

- map the repository to Lokinet-compatible keyfile expectations
- add migration or import paths from upstream identity artifacts
- reduce transient secret copies further when the persisted identity format is redesigned
- add import or migration support from existing Lokinet key artifacts into the internal identity repository
- build higher-level protocol message types on top of `IdentityProof`

## Files and Crates Involved

- `crates/saferunnet-identity`
