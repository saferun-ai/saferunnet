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
- verified decode path as the safe default for service messages, authenticating the signed lower-level envelope before typed service-payload parsing
- explicit unverified decode path for bounded low-level handling and tests
- signer/proof/payload consistency checks during service-message verification
- dedicated `ServiceMessageKind::RouterAnnouncement` alongside the existing `Announcement` kind
- dedicated `ServiceMessageKind::LinkPathControl` for typed link-facing control payloads
- downstream typed consumers now exist in `saferunnet-router` and `saferunnet-link`

## Partially Implemented Items

- the service body is still opaque bytes at this layer even when downstream crates impose richer typed payload contracts
- only three message kinds exist so far: `Announcement`, `RouterAnnouncement`, and `LinkPathControl`

## Not Yet Implemented

- broader link negotiation or session messages beyond the first typed path-control family
- service-session lifecycle messages
- compatibility mapping to any upstream Lokinet message formats

## Known Risks

- current service-message payload body is still opaque bytes and not yet decomposed into richer domain-specific message types
- only the router announcement family and first link path-control family currently consume the service boundary
- no app/runtime pipeline uses `saferunnet-service` over a real transport yet

## Test Coverage State

- sign/verify round-trip is covered
- encode/decode round-trip is covered
- verified decode path is covered
- verified decode authentication ordering against tampered payload version/truncation is covered
- tampered signed payload rejection is covered
- mismatched proof signer rejection is covered
- malformed and truncated top-level framing rejection is covered
- dedicated `RouterAnnouncement` service-kind round-trip coverage is present
- dedicated `LinkPathControl` service-kind round-trip coverage is present

## Compatibility Notes

- this is a project-owned higher-level message boundary, not yet a Lokinet wire-compatibility layer

## Next Recommended Tasks

- add more typed router and link-facing message families on top of `AuthenticatedServiceMessage`
- replace opaque `Announcement` bodies with typed payloads when real callers exist
- add cross-crate integration that feeds authenticated service messages into later runtime components

## Files and Crates Involved

- `crates/saferunnet-service`
- `crates/saferunnet-router`
- `crates/saferunnet-link`
- `crates/saferunnet-identity`
- `crates/saferunnet-crypto`
