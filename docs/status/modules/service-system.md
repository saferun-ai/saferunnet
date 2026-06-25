# Service System Status

## Purpose

Define higher-level authenticated protocol message objects without leaking raw signing, proof, or framing details into later router and service logic.

## Public Interfaces

- `ServiceMessageKind`
- `AuthenticatedServiceMessage`
- `ServiceMessageError`

## Implemented Items

- `saferunnet-service` is now an active workspace crate
- authenticated service-message signing on top of `NodeIdentity`
- deterministic project-owned payload encoding for service messages
- deterministic top-level framing that composes `IdentityProof` and `SignedEnvelope`
- verified decode path as the safe default for service messages
- explicit unverified decode path for bounded low-level handling and tests
- signer/proof/payload consistency checks during service-message verification

## Partially Implemented Items

- only one message kind (`Announcement`) exists so far
- framing exists for authenticated service messages, but no router/link-specific message families exist yet

## Not Yet Implemented

- router control messages
- link negotiation messages
- service-session lifecycle messages
- compatibility mapping to any upstream Lokinet message formats

## Known Risks

- current service-message payload body is still opaque bytes and not yet decomposed into richer domain-specific message types
- no cross-crate runtime integration uses `saferunnet-service` yet

## Test Coverage State

- sign/verify round-trip is covered
- encode/decode round-trip is covered
- verified decode path is covered
- tampered signed payload rejection is covered
- mismatched proof signer rejection is covered
- malformed and truncated top-level framing rejection is covered

## Compatibility Notes

- this is a project-owned higher-level message boundary, not yet a Lokinet wire-compatibility layer

## Next Recommended Tasks

- build router/link-facing message types on top of `AuthenticatedServiceMessage`
- replace opaque announcement bodies with typed message payloads when real callers exist
- add cross-crate integration that feeds authenticated service messages into later runtime components

## Files and Crates Involved

- `crates/saferunnet-service`
- `crates/saferunnet-identity`
- `crates/saferunnet-crypto`
