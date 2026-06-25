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
- explicit declared service dependency checks before wiring

## Partially Implemented Items

- service registration exists, and basic dependency declaration is enforced, but contracts are still string-key based

## Not Yet Implemented

- richer module error categories
- rollback handling for partial wire/setup failures
- richer typed dependency descriptors beyond string keys

## Known Risks

- avoid hidden god-object growth in the kernel

## Test Coverage State

- lifecycle ordering tests pass
- duplicate start protection is covered
- service wiring before startup is covered
- startup rollback on module failure is covered
- missing declared service dependencies are rejected before wiring

## Compatibility Notes

- internal runtime boundary only; no direct Lokinet compatibility requirement yet

## Next Recommended Tasks

- add structured shutdown rollback
- replace string-key dependency contracts with richer typed descriptors
- add richer module error categories

## Files and Crates Involved

- `crates/saferunnet-app`
- `crates/saferunnet-core`
