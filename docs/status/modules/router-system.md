# Router System Status

## Purpose

Define the first typed router-facing protocol family on top of `saferunnet-service` without introducing transport, socket, or link-layer concerns yet.

## Public Interfaces

- `RouterCapability`
- `RouterAnnouncement`
- `AuthenticatedRouterAnnouncement`
- `RouterAnnouncementError`

## Implemented Items

- `saferunnet-router` is now an active workspace crate
- deterministic project-owned router announcement payload framing
- `RouterCapability` enum with `Relay` and `Exit`
- `RouterAnnouncement` typed payload with `sequence` and `capabilities`
- `AuthenticatedRouterAnnouncement` wrapper over `AuthenticatedServiceMessage`
- safe verified decode as the default, with explicit unverified and verified decode entry points
- verification that enforces lower-level service-message verification, the dedicated `RouterAnnouncement` service kind, exact body equality, and duplicate-capability rejection

## Partially Implemented Items

- only one router message family exists so far
- router payload framing is specific to announcements and not yet generalized across future families

## Not Yet Implemented

- router handshake or control families beyond announcements
- link protocol message types
- transport/runtime integration
- compatibility mapping to upstream Lokinet router messages

## Known Risks

- capability ordering is preserved as encoded, so future callers need to decide whether ordering carries semantic meaning
- no higher runtime layer consumes router announcements yet

## Test Coverage State

- sign/verify round-trip is covered
- encode/decode round-trip is covered
- wrong lower-level service kind rejection is covered
- tampered signed payload rejection is covered
- duplicate capability rejection is covered
- malformed router payload rejection for unsupported capability ids and trailing bytes is covered
- unsupported and truncated router payload rejection is covered

## Compatibility Notes

- this is a project-owned typed router boundary, not a socket or wire-compatibility layer

## Next Recommended Tasks

- add the next typed router family that shares this authenticated boundary
- define the first link-facing typed message layer above or beside router announcements as architecture requires
- connect router announcements to a higher runtime component once a consumer exists

## Files and Crates Involved

- `crates/saferunnet-router`
- `crates/saferunnet-service`
- `crates/saferunnet-identity`
- `crates/saferunnet-crypto`
