# App Kernel Status

## Purpose

Own startup, shutdown, state transitions, and module orchestration.

## Public Interfaces

- `AppKernel`
- `RuntimeModule`
- `LifecycleState`

## Implemented Items

- lifecycle state machine
- module registration
- startup ordering
- reverse shutdown ordering

## Partially Implemented Items

- none yet

## Not Yet Implemented

- lifecycle state machine
- module startup/shutdown ordering
- shutdown rollback

## Known Risks

- avoid hidden god-object growth in the kernel

## Test Coverage State

- lifecycle ordering tests pass
- duplicate start protection is covered

## Compatibility Notes

- internal runtime boundary only; no direct Lokinet compatibility requirement yet

## Next Recommended Tasks

- add structured shutdown rollback
- introduce service dependency wiring
- add richer module error categories

## Files and Crates Involved

- `crates/saferunnet-app`
- `crates/saferunnet-core`
