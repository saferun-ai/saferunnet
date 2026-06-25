# saferunnet-link

`saferunnet-link` is the typed link-facing protocol crate layered on top of `saferunnet-service`.

## Implemented

- `PathControlMessage` with the first `Ping(PathPing)` variant
- `PathPing` with deterministic `request_id: u64`
- `AuthenticatedPathControlMessage` on top of `AuthenticatedServiceMessage`
- `SessionHopId` as the shared typed 16-byte link session hop identifier
- `SessionTag` as the shared typed `u32` link session tag
- `SessionInitMessage` carrying initiator identity, local pivot, remote pivot, and optional auth token
- `AuthenticatedSessionInitMessage` on top of `AuthenticatedServiceMessage`
- `SessionPathSwitchMessage` carrying local pivot, remote pivot, and session tag
- `AuthenticatedSessionPathSwitchMessage` on top of `AuthenticatedServiceMessage`
- deterministic project-owned binary framing for link path-control payloads
- deterministic project-owned binary framing for typed session-init payloads
- deterministic project-owned binary framing for typed session-path-switch payloads
- safe verified decode by default with explicit unverified and verified decode entry points
- verification that enforces the dedicated lower-level `ServiceMessageKind::LinkPathControl`
- verification that enforces the dedicated lower-level `ServiceMessageKind::LinkSessionInit`
- verification that enforces the dedicated lower-level `ServiceMessageKind::LinkSessionPathSwitch`
- rejection of tampered payloads, unsupported variant ids, unsupported payload versions, unexpected service kinds, trailing payload bytes, truncated payloads, unsupported initiator algorithm ids, malformed auth-token framing, and malformed session-path-switch payload framing

## Path-Control Payload Framing

- version: `u8`
- variant id: `u8`
- ping request id: `u64` big-endian

## Session-Init Payload Framing

- version: `u8`
- initiator algorithm id: `u8`
- initiator public key: 32 bytes
- local pivot hop id: 16 bytes
- remote pivot hop id: 16 bytes
- auth-token present flag: `u8`
- if auth-token present:
  - auth-token length: `u16` big-endian
  - auth-token bytes

## Session-Path-Switch Payload Framing

- version: `u8`
- local pivot hop id: 16 bytes
- remote pivot hop id: 16 bytes
- session tag: `u32` big-endian

## Compatibility Notes

- this slice is inspired by Lokinet `path_control` / `path_ping` semantics
- the session-init slice is inspired by Lokinet `InitiateSession` inner payload semantics (`i`, `p`, `r`, `u`)
- the session-path-switch slice is inspired by Lokinet `SessionPathSwitch` semantics (`p`, `r`, `t`)
- the framing and typed APIs are project-owned and not wire-compatible with upstream Lokinet

## Not Yet Implemented

- additional path-control variants beyond `Ping`
- DH encryption, transport, or runtime session wiring for session-init
- runtime consumers of session-path-switch messages
- other typed link protocol families beyond path control, session-init, and session-path-switch
- any transport, socket, or runtime integration
- compatibility mapping to upstream Lokinet link messages
