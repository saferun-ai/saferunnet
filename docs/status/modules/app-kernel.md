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
- module-provided service registration before dependency wiring
- module wiring before startup
- startup failure rollback for previously started modules
- explicit declared service dependency checks before wiring
- identity service publication into the runtime registry
- runtime identity bootstrap can now be composed from daemon-supplied settings without leaking config types into the kernel crate
- link-message dispatcher service publication into the runtime registry through a dedicated `LinkMessageModule` seam

## Partially Implemented Items

- service registration exists, and basic dependency declaration is enforced, but contracts are still string-key based

## Not Yet Implemented

- richer module error categories
- rollback handling for partial service-registration or wire failures
- richer typed dependency descriptors beyond string keys

## Known Risks

- avoid hidden god-object growth in the kernel

## Test Coverage State

- lifecycle ordering tests pass
- duplicate start protection is covered
- module-published services are available to dependents before startup
- service wiring before startup is covered
- startup rollback on module failure is covered
- missing declared service dependencies are rejected before wiring
- runtime-identity module construction from daemon-supplied settings is covered indirectly through CLI bootstrap tests
- runtime link-message dispatcher publication before dependent module startup is covered
- dependent runtime modules decoding all current authenticated link families through the dispatcher seam is covered
- missing declared dispatcher dependency without registering the link module is rejected before wiring

## Compatibility Notes

- internal runtime boundary only; no direct Lokinet compatibility requirement yet

## Next Recommended Tasks

- add rollback handling for service-registration failures
- replace string-key dependency contracts with richer typed descriptors
- add richer module error categories

## Files and Crates Involved

- `crates/saferunnet-app`
- `crates/saferunnet-core`
