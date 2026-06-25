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

## Partially Implemented Items

- validation exists for a small subset of fields only

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

## Compatibility Notes

- must preserve valuable Lokinet config semantics while improving diagnostics

## Next Recommended Tasks

- add richer validation rules
- add compatibility fixtures from real Lokinet samples
- add config source layering if Lokinet compatibility requires it

## Files and Crates Involved

- `crates/saferunnet-config`
- `crates/saferunnet-compat-lokinet`
