# Config System Status

## Purpose

Load Lokinet-style configuration, validate it, and normalize it for internal runtime use.

## Public Interfaces

- `load_from_str`
- `NormalizedConfig`
- `RawLokinetConfig`

## Implemented Items

- minimal Lokinet-style section parser
- typed normalized configuration model
- default router and logging values
- actionable line-number parse diagnostics

## Partially Implemented Items

- none yet

## Not Yet Implemented

- compatibility parser
- normalization rules
- diagnostics

## Known Risks

- accidental leakage of compatibility-only structures into runtime code

## Test Coverage State

- config normalization defaults are covered
- invalid line diagnostics are covered

## Compatibility Notes

- must preserve valuable Lokinet config semantics while improving diagnostics

## Next Recommended Tasks

- add file-based loading APIs
- add richer validation rules
- add compatibility fixtures from real Lokinet samples

## Files and Crates Involved

- `crates/saferunnet-config`
- `crates/saferunnet-compat-lokinet`
