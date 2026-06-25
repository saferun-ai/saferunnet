# saferunnet-link

`saferunnet-link` is the first typed link-facing protocol crate layered on top of `saferunnet-service`.

## Implemented

- `PathControlMessage` with the first `Ping(PathPing)` variant
- `PathPing` with deterministic `request_id: u64`
- `AuthenticatedPathControlMessage` on top of `AuthenticatedServiceMessage`
- deterministic project-owned binary framing for link path-control payloads
- safe verified decode by default with explicit unverified and verified decode entry points
- verification that enforces the dedicated lower-level `ServiceMessageKind::LinkPathControl`
- rejection of tampered payloads, unsupported variant ids, unsupported payload versions, unexpected service kinds, trailing payload bytes, and truncated payloads

## Path-Control Payload Framing

- version: `u8`
- variant id: `u8`
- ping request id: `u64` big-endian

## Compatibility Notes

- this slice is inspired by Lokinet `path_control` / `path_ping` semantics
- the framing and typed API are project-owned and not wire-compatible with upstream Lokinet

## Not Yet Implemented

- additional path-control variants beyond `Ping`
- other typed link protocol families
- any transport, socket, or runtime integration
- compatibility mapping to upstream Lokinet link messages
