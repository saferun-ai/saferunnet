# App Kernel Status

## Purpose

Own startup, shutdown, state transitions, and module orchestration.

## Public Interfaces

- `AppKernel`
- `RuntimeModule`
- `LifecycleState`
- `ServiceRegistry`

## Implemented Items

- lifecycle state machine
- module registration
- startup ordering
- reverse shutdown ordering
- typed service registry
- module wiring before startup
- startup failure rollback for previously started modules

## Partially Implemented Items

- service registration exists, but dependency policies between modules are still shallow

## Not Yet Implemented

- richer module error categories
- declarative service dependency contracts
- rollback handling for partial wire/setup failures

## Known Risks

- avoid hidden god-object growth in the kernel

## Test Coverage State

- lifecycle ordering tests pass
- duplicate start protection is covered
- service wiring before startup is covered
- startup rollback on module failure is covered

## Compatibility Notes

- internal runtime boundary only; no direct Lokinet compatibility requirement yet

## Next Recommended Tasks

- add structured shutdown rollback
- expand service dependency contracts beyond type lookup
- add richer module error categories

## Files and Crates Involved

- `crates/saferunnet-app`
- `crates/saferunnet-core`
