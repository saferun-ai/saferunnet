# Link System Status

## Purpose

Define the first typed link-facing protocol families in `saferunnet-service` and the first minimal runtime session-state seam, without introducing transport, socket, or DH encryption work yet.

## Public Interfaces

- `PathControlMessage`
- `PathPing`
- `AuthenticatedPathControlMessage`
- `PathControlError`
- `SessionHopId`
- `SessionTag`
- `SessionInitMessage`
- `AuthenticatedSessionInitMessage`
- `SessionInitError`
- `SessionAcceptMessage`
- `AuthenticatedSessionAcceptMessage`
- `SessionAcceptError`
- `SessionPathSwitchMessage`
- `AuthenticatedSessionPathSwitchMessage`
- `SessionPathSwitchError`
- `SessionCloseMessage`
- `AuthenticatedSessionCloseMessage`
- `SessionCloseError`
- `SessionState`
- `SessionStateError`
- `ActiveSession`
- `AuthenticatedLinkMessage`
- `LinkMessageError`

## Implemented Items

- typed link families and unified dispatch now live directly in `saferunnet-service`
- `saferunnet-link` is no longer an active workspace crate and now serves as a placeholder directory
- deterministic project-owned path-control payload framing
- deterministic project-owned session-init payload framing
- deterministic project-owned session-accept payload framing
- deterministic project-owned session-path-switch payload framing
- deterministic project-owned session-close payload framing
- `PathControlMessage::Ping(PathPing)` as the first typed link-facing control variant
- `PathPing` typed payload with `request_id: u64`
- `AuthenticatedPathControlMessage` wrapper over `AuthenticatedServiceMessage`
- shared `SessionHopId` typed payload helper over a 16-byte hop id
- shared `SessionTag` typed payload helper over a `u32` session tag
- `SessionInitMessage` typed payload carrying initiator identity, local pivot hop id, remote pivot hop id, and optional auth token
- `AuthenticatedSessionInitMessage` wrapper over `AuthenticatedServiceMessage`
- `SessionAcceptMessage` typed payload carrying only a session tag, following the current upstream semantic reference
- `AuthenticatedSessionAcceptMessage` wrapper over `AuthenticatedServiceMessage`
- `SessionPathSwitchMessage` typed payload carrying local pivot hop id, remote pivot hop id, and session tag
- `AuthenticatedSessionPathSwitchMessage` wrapper over `AuthenticatedServiceMessage`
- `SessionCloseMessage` typed payload carrying only a session tag, following the current upstream semantic reference
- `AuthenticatedSessionCloseMessage` wrapper over `AuthenticatedServiceMessage`
- `SessionState` as a pure in-memory service-owned component that records pending init messages, promotes accepted sessions, applies path switches by tag, and removes active sessions by close tag
- `ActiveSession` snapshots exposed for deterministic assertions without app-kernel setup
- `AuthenticatedLinkMessage` unified typed decode/dispatch boundary over current authenticated link families
- `LinkMessageError` typed error boundary for lower-level service decode/auth errors, unsupported service kinds, and family-specific typed decode failures
- safe verified decode as the default, with explicit unverified and verified decode entry points
- verified decode authenticates the lower-level service message before typed path-control parsing
- verified decode authenticates the lower-level service message before typed session-init parsing
- verified decode authenticates the lower-level service message before typed session-accept parsing
- verified decode authenticates the lower-level service message before typed session-path-switch parsing
- verified decode authenticates the lower-level service message before typed session-close parsing
- unified dispatcher decodes `AuthenticatedServiceMessage` once, branches by `ServiceMessageKind`, and then performs family-specific typed parsing
- wrapper verification enforces lower-level service-message verification, the dedicated `LinkPathControl` service kind, and exact body equality
- wrapper verification enforces lower-level service-message verification, the dedicated `LinkSessionInit` service kind, and exact body equality
- wrapper verification enforces lower-level service-message verification, the dedicated `LinkSessionAccept` service kind, and exact body equality
- wrapper verification enforces lower-level service-message verification, the dedicated `LinkSessionPathSwitch` service kind, and exact body equality
- wrapper verification enforces lower-level service-message verification, the dedicated `LinkSessionClose` service kind, and exact body equality
- typed path-control dispatch rejects unsupported variants, unsupported versions, truncated ping bodies, and trailing payload bytes
- typed session-init dispatch rejects unsupported initiator algorithm ids, malformed auth-token framing, truncated auth-token payloads, and trailing payload bytes
- typed session-accept dispatch rejects unsupported versions, truncated payloads, and trailing payload bytes
- typed session-path-switch dispatch rejects unsupported versions, truncated payloads, and trailing payload bytes
- typed session-close dispatch rejects unsupported versions, truncated payloads, and trailing payload bytes
- first app/runtime consumer seam for unified link decode via `saferunnet-app::LinkMessageDispatcher`, now backed directly by `saferunnet-service`
- `saferunnet-app::LinkMessageModule` runtime publication path for the dispatcher through `ServiceRegistry`
- first app/runtime session-state seam via `saferunnet-app::LinkSessionStateModule`, publishing shared in-memory state through `ServiceRegistry`

## Partially Implemented Items

- only one link path-control variant exists so far
- only one typed session-init family exists so far
- only one typed session-accept family exists so far
- only one typed session-path-switch family exists so far
- only one typed session-close family exists so far
- link payload framing is still family-specific and not yet shared across later link families
- session state is still intentionally in-memory only and does not coordinate multiple peers or transports yet

## Not Yet Implemented

- additional path-control variants beyond ping
- DH encryption, transport, peer IO, or persistence for the current session lifecycle families
- additional typed link session negotiation or circuit-building families
- transport/runtime integration
- compatibility mapping to upstream Lokinet link messages

## Known Risks

- later path-control variants may need a payload structure richer than the current fixed-width ping body
- later link families may want a shared framing helper instead of per-family framing code
- the runtime seam now includes state publication, but orchestration is still caller-driven and intentionally minimal

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
- session-accept sign/verify round-trip is covered
- session-accept encode/decode round-trip is covered
- session-accept wrong lower-level service kind rejection is covered
- session-accept tampered signed payload rejection is covered
- session-accept unsupported, truncated, and trailing-bytes payload rejection is covered
- session-accept verified decode authentication ordering against tampered typed payloads is covered
- session-path-switch sign/verify round-trip is covered
- session-path-switch encode/decode round-trip is covered
- session-path-switch wrong lower-level service kind rejection is covered
- session-path-switch tampered signed payload rejection is covered
- session-path-switch unsupported, truncated, and trailing-bytes payload rejection is covered
- session-path-switch verified decode authentication ordering against tampered typed payloads is covered
- session-close sign/verify round-trip is covered
- session-close encode/decode round-trip is covered
- session-close wrong lower-level service kind rejection is covered
- session-close tampered signed payload rejection is covered
- session-close unsupported, truncated, and trailing-bytes payload rejection is covered
- session-close verified decode authentication ordering against tampered typed payloads is covered
- unified link-message decode/dispatch round-trip for path-control, session-init, session-accept, session-path-switch, and session-close is covered
- unified dispatcher rejection of non-link service kinds is covered
- unified verified decode preference for lower-level auth failure over typed parse failure is covered
- unified unverified decode surfacing of family-specific typed parse errors is covered
- runtime-kernel wiring for dispatcher publication and consumption is covered
- pure session-state record/promote/path-switch/close behavior is covered
- runtime consumer decode coverage for path-control, session-init, session-accept, session-path-switch, and session-close through the dispatcher seam is covered
- runtime consumer lifecycle driving of init -> accept -> path-switch -> close through dispatcher plus state seam is covered
- missing runtime dispatcher dependency contracts are rejected when the provider module is not registered

## Compatibility Notes

- this slice is inspired by Lokinet `path_control` / `path_ping` semantics
- the session-init slice is inspired by Lokinet `InitiateSession` inner payload semantics (`i`, `p`, `r`, `u`)
- the session-accept slice is inspired by Lokinet `InitiateSession::serialize_response` / `deserialize_response`, where the response currently carries only the session tag
- the session-path-switch slice is inspired by Lokinet `SessionPathSwitch` inner payload semantics (`p`, `r`, `t`)
- the session-close slice is inspired by Lokinet `CloseSession` semantics carrying a session tag
- the framing and typed APIs are project-owned and not wire-compatible with upstream Lokinet

## Next Recommended Tasks

- add the next typed path-control variant only when a concrete consumer exists
- keep the session-state seam pure while deciding the next caller-facing coordinator around init -> accept -> path-switch -> close
- define the next typed session family beside session-init, session-accept, session-path-switch, and session-close only when runtime needs it first
- connect typed link control and the current session lifecycle families to a higher runtime component once a concrete transport consumer exists
- decide whether later link session work should share a common framing helper across typed families

## Files and Crates Involved

- `crates/saferunnet-service`
- `crates/saferunnet-identity`
- `crates/saferunnet-crypto`
- `crates/saferunnet-app`
