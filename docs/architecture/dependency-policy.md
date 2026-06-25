# Dependency Policy

## Rules

1. Prefer the standard library before adding crates.
2. Prefer one mature crate over several narrowly overlapping crates.
3. Prefer an internal workspace crate when a third-party option would fragment ownership.
4. Any new dependency must explain why an internal implementation is worse.
5. Parser, protocol, and compatibility glue should stay project-owned where practical.

## Approved Foundation Dependencies

- `thiserror`
- `tracing`
- `tracing-subscriber`

## Deferred Decisions

- async runtime
- CLI framework
- serialization framework
- crypto backend
