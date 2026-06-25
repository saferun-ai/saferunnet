# saferunnet-link (placeholder)

This directory is intentionally no longer an active workspace crate.

The typed link families and unified link-message dispatcher were converged into
`crates/saferunnet-service` as part of the final link/service convergence slice on 2026-06-25.
`saferunnet-app` now depends directly on `saferunnet-service` for the runtime link decode seam.

Current public API location:

- `saferunnet_service::PathControlMessage`
- `saferunnet_service::PathPing`
- `saferunnet_service::AuthenticatedPathControlMessage`
- `saferunnet_service::SessionHopId`
- `saferunnet_service::SessionTag`
- `saferunnet_service::SessionInitMessage`
- `saferunnet_service::AuthenticatedSessionInitMessage`
- `saferunnet_service::SessionPathSwitchMessage`
- `saferunnet_service::AuthenticatedSessionPathSwitchMessage`
- `saferunnet_service::AuthenticatedLinkMessage`
- `saferunnet_service::LinkMessageError`
