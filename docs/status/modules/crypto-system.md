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
- 32-byte hex decoding and encoding
- invalid hex and length diagnostics
- project-owned key generation contract and generated key-pair shape

## Partially Implemented Items

- algorithm support exists only for Ed25519 right now
- generation is injectable by contract only; there is no concrete cryptographic backend yet

## Not Yet Implemented

- signature operations
- curve conversion or DH helpers
- blinded key support

## Known Risks

- current implementation validates shape, not cryptographic correctness
- a real key-generation backend still needs to be selected and isolated behind the existing trait

## Test Coverage State

- public key hex round-trip is covered
- secret key length rejection is covered
- generation contract behavior is exercised through identity bootstrap tests

## Compatibility Notes

- naming aligns with Lokinet's Ed25519 identity usage, but this crate does not yet implement signing or real key generation

## Next Recommended Tasks

- implement one concrete Ed25519 generator behind `KeyGenerator`
- add signing and verification contracts
- add blinded or transport-key abstractions only when callers exist

## Files and Crates Involved

- `crates/saferunnet-crypto`
