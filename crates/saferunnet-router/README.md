# saferunnet-router

`saferunnet-router` is the first typed router protocol crate layered on top of `saferunnet-service`.

## Implemented

- `RouterCapability` with `Relay` and `Exit`
- `RouterAnnouncement` with `sequence` and `capabilities`
- `AuthenticatedRouterAnnouncement` on top of `AuthenticatedServiceMessage`
- deterministic project-owned binary framing for router announcements
- safe verified decode by default with explicit unverified and verified decode entry points
- verification that enforces the dedicated lower-level `ServiceMessageKind::RouterAnnouncement`
- rejection of tampered payloads, duplicate capabilities, unsupported capability ids, trailing payload bytes, unsupported payload versions, and truncated payloads

## Router Payload Framing

- version: `u8`
- sequence: `u64` big-endian
- capability count: `u16` big-endian
- capability ids: repeated `u8`

## Not Yet Implemented

- additional router message families
- link negotiation messages
- any transport, socket, or runtime integration
- compatibility mapping to upstream Lokinet router messages
