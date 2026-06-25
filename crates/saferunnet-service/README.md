# saferunnet-service

Project-owned authenticated messaging subsystem built on top of `saferunnet-identity` and
`saferunnet-crypto`.

This crate owns:

- `AuthenticatedServiceMessage` and `ServiceMessageKind`
- the router-announcement typed family:
  - `RouterCapability`
  - `RouterAnnouncement`
  - `AuthenticatedRouterAnnouncement`
  - `RouterAnnouncementError`
