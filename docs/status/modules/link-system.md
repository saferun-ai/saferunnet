# Link System Status

## Purpose

Define the first typed link-facing control family on top of `saferunnet-service` without introducing transport, socket, or session-management concerns yet.

## Public Interfaces

- `PathControlMessage`
- `PathPing`
- `AuthenticatedPathControlMessage`
- `PathControlError`

## Implemented Items

- `saferunnet-link` is now an active workspace crate
- deterministic project-owned path-control payload framing
- `PathControlMessage::Ping(PathPing)` as the first typed link-facing control variant
- `PathPing` typed payload with `request_id: u64`
- `AuthenticatedPathControlMessage` wrapper over `AuthenticatedServiceMessage`
- safe verified decode as the default, with explicit unverified and verified decode entry points
- verified decode authenticates the lower-level service message before typed path-control parsing
- wrapper verification enforces lower-level service-message verification, the dedicated `LinkPathControl` service kind, and exact body equality
- typed path-control dispatch rejects unsupported variants, unsupported versions, truncated ping bodies, and trailing payload bytes

## Partially Implemented Items

- only one link path-control variant exists so far
- link payload framing is specific to path control and not yet shared with later link families

## Not Yet Implemented

- additional path-control variants beyond ping
- typed link session, negotiation, or circuit-building families
- transport/runtime integration
- compatibility mapping to upstream Lokinet link messages

## Known Risks

- later path-control variants may need a payload structure richer than the current fixed-width ping body
- no higher runtime layer consumes typed link control messages yet

## Test Coverage State

- sign/verify round-trip is covered
- encode/decode round-trip is covered
- wrong lower-level service kind rejection is covered
- tampered signed payload rejection is covered
- verified decode authentication ordering against tampered unsupported variants is covered
- unsupported path-control variant rejection is covered
- unsupported, truncated, and trailing-bytes payload rejection is covered

## Compatibility Notes

- this slice is inspired by Lokinet `path_control` / `path_ping` semantics
- the framing and typed API are project-owned and not wire-compatible with upstream Lokinet

## Next Recommended Tasks

- add the next typed path-control variant only when a concrete consumer exists
- define the next independent link-facing family beside path control if runtime needs it first
- connect typed link control messages to a higher runtime component once a consumer exists

## Files and Crates Involved

- `crates/saferunnet-link`
- `crates/saferunnet-service`
- `crates/saferunnet-identity`
- `crates/saferunnet-crypto`
