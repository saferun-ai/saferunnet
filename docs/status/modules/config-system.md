# Config System Status

## Purpose

Load Lokinet-style configuration, validate it, and normalize it for internal runtime use.

## Public Interfaces

- `load_from_str`
- `load_from_file`
- `NormalizedConfig`
- `RawLokinetConfig`

## Implemented Items

- minimal Lokinet-style section parser
- typed normalized configuration model
- default router and logging values
- actionable line-number parse diagnostics
- file-based config loading
- blank router nickname validation
- `conf.d`-style layered path loading
- repeated `network.exit-node` preservation
- normalized `network.keyfile`, `network.ifaddr`, and `network.exit_nodes`
- fixture-backed compatibility checks based on upstream Lokinet sample fragments
- validation for `network.ifaddr`, `network.hops`, and `network.paths`
- validation that `network.exit=true` requires `network.ifaddr`
- daemon-side bootstrap now resolves relative `router.data_dir` and `network.keyfile` paths into runtime identity settings

## Partially Implemented Items

- validation exists for a small subset of fields only
- repeated-key preservation exists, but only a subset is normalized into typed fields

## Not Yet Implemented

- broader normalization rules
- richer compatibility fixtures
- multi-file or environment-aware config resolution

## Known Risks

- accidental leakage of compatibility-only structures into runtime code

## Test Coverage State

- config normalization defaults are covered
- invalid line diagnostics are covered
- file-based loading is covered
- blank nickname validation is covered
- layered config merging is covered
- Lokinet-style fixture loading is covered
- exit/ifaddr validation is covered
- hops/paths validation is covered
- CLI bootstrap tests cover relative keyfile resolution and default keyfile placement under resolved data directories

## Compatibility Notes

- must preserve valuable Lokinet config semantics while improving diagnostics

## Next Recommended Tasks

- add richer validation rules
- expand compatibility fixtures from real Lokinet samples
- add config source layering if Lokinet compatibility requires it
- expose path-resolution helpers in a more reusable bootstrap surface if more runtime modules need config-derived filesystem paths

## Files and Crates Involved

- `crates/saferunnet-config`
- `crates/saferunnet-compat-lokinet`
