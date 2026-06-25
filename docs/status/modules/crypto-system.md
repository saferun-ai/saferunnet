# Crypto System Status

## Purpose

Define project-owned cryptographic key material contracts without forcing the rest of the runtime to know storage or wire-format details.

## Public Interfaces

- `KeyAlgorithm`
- `KeyGenerator`
- `KeyPair`
- `PublicKey`
- `SecretKey`

## Implemented Items

- opaque Ed25519 key material types
- 32-byte key byte import and export helpers
- 32-byte hex decoding and encoding
- invalid hex and length diagnostics
- project-owned key generation contract and generated key-pair shape
- concrete Ed25519 generator backed by `ed25519-dalek`
- redacted `SecretKey` debug output and zeroization on drop

## Partially Implemented Items

- algorithm support exists only for Ed25519 right now
- generation is injectable by contract, but only one concrete backend exists so far

## Not Yet Implemented

- signature operations
- curve conversion or DH helpers
- blinded key support

## Known Risks

- current implementation validates shape, not cryptographic correctness
- current concrete backend is intentionally isolated, but backend replacement tests do not exist yet
- `SecretKey` still supports cloning because upstream runtime contracts currently pass owned values around
- `SecretKey::to_bytes` and `SecretKey::to_hex` still expose explicit raw copies for callers that need serialization or backend interop

## Test Coverage State

- public key hex round-trip is covered
- secret key length rejection is covered
- public and secret key byte round-trips are covered
- concrete Ed25519 generator output consistency is covered
- secret-key debug redaction is covered
- streaming hex append behavior is covered
- generation contract behavior is exercised through identity bootstrap tests

## Compatibility Notes

- naming aligns with Lokinet's Ed25519 identity usage, and real key generation now exists behind project-owned contracts; signing is still not exposed yet

## Next Recommended Tasks

- add signing and verification contracts
- add backend-isolation tests around signing and verification so future provider swaps stay safe
- add blinded or transport-key abstractions only when callers exist

## Files and Crates Involved

- `crates/saferunnet-crypto`
