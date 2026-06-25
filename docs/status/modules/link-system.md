# Link System Status

## Purpose

Define the first typed link-facing protocol families on top of `saferunnet-service` without introducing transport, socket, DH encryption, or runtime session-management concerns yet.

## Public Interfaces

- `PathControlMessage`
- `PathPing`
- `AuthenticatedPathControlMessage`
- `PathControlError`
- `SessionHopId`
- `SessionInitMessage`
- `AuthenticatedSessionInitMessage`
- `SessionInitError`

## Implemented Items

- `saferunnet-link` is now an active workspace crate
- deterministic project-owned path-control payload framing
- deterministic project-owned session-init payload framing
- `PathControlMessage::Ping(PathPing)` as the first typed link-facing control variant
- `PathPing` typed payload with `request_id: u64`
- `AuthenticatedPathControlMessage` wrapper over `AuthenticatedServiceMessage`
- `SessionHopId` typed payload helper over a 16-byte hop id
- `SessionInitMessage` typed payload carrying initiator identity, local pivot hop id, remote pivot hop id, and optional auth token
- `AuthenticatedSessionInitMessage` wrapper over `AuthenticatedServiceMessage`
- safe verified decode as the default, with explicit unverified and verified decode entry points
- verified decode authenticates the lower-level service message before typed path-control parsing
- verified decode authenticates the lower-level service message before typed session-init parsing
- wrapper verification enforces lower-level service-message verification, the dedicated `LinkPathControl` service kind, and exact body equality
- wrapper verification enforces lower-level service-message verification, the dedicated `LinkSessionInit` service kind, and exact body equality
- typed path-control dispatch rejects unsupported variants, unsupported versions, truncated ping bodies, and trailing payload bytes
- typed session-init dispatch rejects unsupported initiator algorithm ids, malformed auth-token framing, truncated auth-token payloads, and trailing payload bytes

## Partially Implemented Items

- only one link path-control variant exists so far
- only one typed session-init family exists so far
- link payload framing is still family-specific and not yet shared across later link families

## Not Yet Implemented

- additional path-control variants beyond ping
- DH encryption, transport, or runtime session wiring for the session-init family
- additional typed link session, negotiation, or circuit-building families
- transport/runtime integration
- compatibility mapping to upstream Lokinet link messages

## Known Risks

- later path-control variants may need a payload structure richer than the current fixed-width ping body
- later link families may want a shared framing helper instead of per-family framing code
- no higher runtime layer consumes typed link control or session-init messages yet

## Test Coverage State

- sign/verify round-trip is covered
- encode/decode round-trip is covered
- wrong lower-level service kind rejection is covered
- tampered signed payload rejection is covered
- verified decode authentication ordering against tampered unsupported variants is covered
- unsupported path-control variant rejection is covered
- unsupported, truncated, and trailing-bytes payload rejection is covered
- session-init sign/verify round-trip without auth token is covered
- session-init encode/decode round-trip with auth token is covered
- session-init wrong lower-level service kind rejection is covered
- session-init tampered signed payload rejection is covered
- session-init unsupported initiator algorithm rejection is covered
- session-init malformed/truncated auth-token framing rejection is covered
- session-init trailing-bytes rejection is covered
- session-init verified decode authentication ordering against tampered typed payloads is covered

## Compatibility Notes

- this slice is inspired by Lokinet `path_control` / `path_ping` semantics
- the session-init slice is inspired by Lokinet `InitiateSession` inner payload semantics (`i`, `p`, `r`, `u`)
- the framing and typed APIs are project-owned and not wire-compatible with upstream Lokinet

## Next Recommended Tasks

- add the next typed path-control variant only when a concrete consumer exists
- define the next independent link-facing family beside path control and session-init if runtime needs it first
- connect typed link control and session-init messages to a higher runtime component once a consumer exists
- decide whether later link session work should share a common framing helper across typed families

## Files and Crates Involved

- `crates/saferunnet-link`
- `crates/saferunnet-service`
- `crates/saferunnet-identity`
- `crates/saferunnet-crypto`
