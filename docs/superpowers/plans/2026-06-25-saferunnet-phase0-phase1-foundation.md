# Saferunnet Phase 0 and Phase 1 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `saferunnet` Rust workspace foundation, resumability/status system, config compatibility skeleton, and application kernel skeleton with tests so later protocol work lands on a stable architecture.

**Architecture:** Start with a composition-first workspace that separates runtime orchestration, configuration normalization, compatibility parsing, observability, and testing support. Keep the first slice synchronous and trait-oriented so we avoid prematurely locking in an async runtime while still proving lifecycle and configuration boundaries.

**Tech Stack:** Rust stable toolchain, Cargo workspace, standard library, `thiserror`, `tracing`, `tracing-subscriber`, PowerShell verification scripts

---

### Task 1: Initialize Git and the Rust Workspace Skeleton

**Files:**
- Create: `.gitignore`
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `apps/saferunnetd/Cargo.toml`
- Create: `apps/saferunnetd/src/main.rs`
- Create: `crates/saferunnet-app/Cargo.toml`
- Create: `crates/saferunnet-app/src/lib.rs`
- Create: `crates/saferunnet-core/Cargo.toml`
- Create: `crates/saferunnet-core/src/lib.rs`
- Create: `crates/saferunnet-config/Cargo.toml`
- Create: `crates/saferunnet-config/src/lib.rs`
- Create: `crates/saferunnet-compat-lokinet/Cargo.toml`
- Create: `crates/saferunnet-compat-lokinet/src/lib.rs`
- Create: `crates/saferunnet-observability/Cargo.toml`
- Create: `crates/saferunnet-observability/src/lib.rs`
- Create: `crates/saferunnet-testing/Cargo.toml`
- Create: `crates/saferunnet-testing/src/lib.rs`
- Create: `crates/saferunnet-crypto/README.md`
- Create: `crates/saferunnet-identity/README.md`
- Create: `crates/saferunnet-link/README.md`
- Create: `crates/saferunnet-path/README.md`
- Create: `crates/saferunnet-router/README.md`
- Create: `crates/saferunnet-service/README.md`
- Create: `crates/saferunnet-exit/README.md`
- Create: `crates/saferunnet-dns/README.md`
- Create: `crates/saferunnet-platform/README.md`
- Create: `crates/saferunnet-rpc/README.md`
- Modify: `README.md`

- [ ] **Step 1: Confirm the workspace is still unbootstrapped**

Run:

```powershell
cargo metadata --format-version 1
```

Expected: FAIL with an error equivalent to `could not find Cargo.toml`.

- [ ] **Step 2: Initialize git and generate the crate shell**

Run:

```powershell
git init
cargo new apps/saferunnetd --bin --vcs none
cargo new crates/saferunnet-app --lib --vcs none
cargo new crates/saferunnet-core --lib --vcs none
cargo new crates/saferunnet-config --lib --vcs none
cargo new crates/saferunnet-compat-lokinet --lib --vcs none
cargo new crates/saferunnet-observability --lib --vcs none
cargo new crates/saferunnet-testing --lib --vcs none
New-Item -ItemType Directory -Force 'crates/saferunnet-crypto','crates/saferunnet-identity','crates/saferunnet-link','crates/saferunnet-path','crates/saferunnet-router','crates/saferunnet-service','crates/saferunnet-exit','crates/saferunnet-dns','crates/saferunnet-platform','crates/saferunnet-rpc'
```

Expected: PASS with seven generated Cargo packages and the placeholder directories present.

- [ ] **Step 3: Replace the generated manifests with the workspace root manifest**

Write `Cargo.toml`:

```toml
[workspace]
members = [
  "apps/saferunnetd",
  "crates/saferunnet-app",
  "crates/saferunnet-core",
  "crates/saferunnet-config",
  "crates/saferunnet-compat-lokinet",
  "crates/saferunnet-observability",
  "crates/saferunnet-testing",
]
resolver = "2"

[workspace.package]
edition = "2024"
license = "MIT OR Apache-2.0"
version = "0.1.0"
authors = ["Saferunnet Team"]
repository = "local"

[workspace.dependencies]
thiserror = "2.0"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
```

Write `rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["clippy", "rustfmt"]
profile = "minimal"
```

Write `.gitignore`:

```gitignore
/target
**/*.rs.bk
.DS_Store
Thumbs.db
```

- [ ] **Step 4: Normalize each crate manifest and stub**

Write `apps/saferunnetd/Cargo.toml`:

```toml
[package]
name = "saferunnetd"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true

[[bin]]
name = "saferunnet"
path = "src/main.rs"

[dependencies]
saferunnet-app = { path = "../../crates/saferunnet-app" }
saferunnet-config = { path = "../../crates/saferunnet-config" }
saferunnet-observability = { path = "../../crates/saferunnet-observability" }
```

Write `apps/saferunnetd/src/main.rs`:

```rust
fn main() {
    println!("saferunnet bootstrap");
}
```

Write `crates/saferunnet-app/Cargo.toml`:

```toml
[package]
name = "saferunnet-app"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true

[dependencies]
saferunnet-core = { path = "../saferunnet-core" }
```

Write `crates/saferunnet-app/src/lib.rs`:

```rust
pub fn crate_marker() -> &'static str {
    "saferunnet-app"
}
```

Write `crates/saferunnet-core/Cargo.toml`:

```toml
[package]
name = "saferunnet-core"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true
```

Write `crates/saferunnet-core/src/lib.rs`:

```rust
pub fn crate_marker() -> &'static str {
    "saferunnet-core"
}
```

Write `crates/saferunnet-config/Cargo.toml`:

```toml
[package]
name = "saferunnet-config"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true

[dependencies]
saferunnet-compat-lokinet = { path = "../saferunnet-compat-lokinet" }
saferunnet-core = { path = "../saferunnet-core" }
thiserror.workspace = true
```

Write `crates/saferunnet-config/src/lib.rs`:

```rust
pub fn crate_marker() -> &'static str {
    "saferunnet-config"
}
```

Write `crates/saferunnet-compat-lokinet/Cargo.toml`:

```toml
[package]
name = "saferunnet-compat-lokinet"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true

[dependencies]
thiserror.workspace = true
```

Write `crates/saferunnet-compat-lokinet/src/lib.rs`:

```rust
pub fn crate_marker() -> &'static str {
    "saferunnet-compat-lokinet"
}
```

Write `crates/saferunnet-observability/Cargo.toml`:

```toml
[package]
name = "saferunnet-observability"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true

[dependencies]
tracing.workspace = true
tracing-subscriber.workspace = true
```

Write `crates/saferunnet-observability/src/lib.rs`:

```rust
pub fn crate_marker() -> &'static str {
    "saferunnet-observability"
}
```

Write `crates/saferunnet-testing/Cargo.toml`:

```toml
[package]
name = "saferunnet-testing"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true
```

Write `crates/saferunnet-testing/src/lib.rs`:

```rust
pub fn sample_lokinet_config() -> &'static str {
    "[router]\nnickname=sample-node\n"
}
```

- [ ] **Step 5: Add placeholders for the future phase crates and refresh the root README**

Write each placeholder README with the same template, substituting the crate name:

```md
# saferunnet-crypto

Reserved for a future implementation crate. This directory exists now so the source tree matches the approved architecture before protocol work begins.
```

Repeat for:

```text
saferunnet-identity
saferunnet-link
saferunnet-path
saferunnet-router
saferunnet-service
saferunnet-exit
saferunnet-dns
saferunnet-platform
saferunnet-rpc
```

Replace `README.md` with:

```md
# ReburnSaferunNet

`saferunnet` is the Rust rewrite workspace for the Saferunnet/Lokinet effort.

## Current Status

- Phase: Foundation bootstrap
- Spec: `docs/superpowers/specs/2026-06-25-saferunnet-rewrite-design.md`
- Plan: `docs/superpowers/plans/2026-06-25-saferunnet-phase0-phase1-foundation.md`

## Bootstrap Commands

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
```

- [ ] **Step 6: Verify the workspace now resolves**

Run:

```powershell
cargo metadata --format-version 1
```

Expected: PASS with JSON output containing workspace members including `apps/saferunnetd` and `crates/saferunnet-config`.

- [ ] **Step 7: Commit the bootstrap**

Run:

```powershell
git add .
git commit -m "chore: bootstrap saferunnet workspace"
```

Expected: PASS with an initial commit.

### Task 2: Add Project Layout Checks, Tooling Scripts, and the Status Ledger

**Files:**
- Create: `scripts/check.ps1`
- Create: `scripts/check-project-layout.ps1`
- Create: `docs/architecture/dependency-policy.md`
- Create: `docs/status/roadmap.md`
- Create: `docs/status/current-phase.md`
- Create: `docs/status/modules/app-kernel.md`
- Create: `docs/status/modules/config-system.md`
- Create: `docs/status/session-log/2026-06-25.md`
- Create: `crates/saferunnet-testing/tests/project_layout.rs`

- [ ] **Step 1: Write a failing project-layout test**

Write `crates/saferunnet-testing/tests/project_layout.rs`:

```rust
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace layout")
        .to_path_buf()
}

#[test]
fn required_status_and_script_files_exist() {
    let root = repo_root();
    for relative in [
        "docs/architecture/dependency-policy.md",
        "docs/status/roadmap.md",
        "docs/status/current-phase.md",
        "docs/status/modules/app-kernel.md",
        "docs/status/modules/config-system.md",
        "docs/status/session-log/2026-06-25.md",
        "scripts/check.ps1",
        "scripts/check-project-layout.ps1",
    ] {
        assert!(
            root.join(relative).exists(),
            "missing required path: {relative}"
        );
    }
}
```

- [ ] **Step 2: Run the new test to confirm it fails**

Run:

```powershell
cargo test -p saferunnet-testing required_status_and_script_files_exist
```

Expected: FAIL with `missing required path`.

- [ ] **Step 3: Add the verification scripts**

Write `scripts/check-project-layout.ps1`:

```powershell
$ErrorActionPreference = "Stop"

$required = @(
  "docs/architecture/dependency-policy.md",
  "docs/status/roadmap.md",
  "docs/status/current-phase.md",
  "docs/status/modules/app-kernel.md",
  "docs/status/modules/config-system.md",
  "docs/status/session-log/2026-06-25.md",
  "scripts/check.ps1"
)

foreach ($path in $required) {
  if (-not (Test-Path $path)) {
    throw "Missing required project path: $path"
  }
}

Write-Host "Project layout OK"
```

Write `scripts/check.ps1`:

```powershell
$ErrorActionPreference = "Stop"

./scripts/check-project-layout.ps1
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

Write-Host "All checks passed"
```

- [ ] **Step 4: Add the dependency policy and status ledger files**

Write `docs/architecture/dependency-policy.md`:

```md
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
```

Write `docs/status/roadmap.md`:

```md
# Roadmap

- [x] Architecture spec approved
- [ ] Phase 0 complete
- [ ] Phase 1 complete
- [ ] Phase 2 complete
- [ ] Phase 3 complete
- [ ] Phase 4 complete
- [ ] Phase 5 complete
- [ ] Phase 6 complete

## Current Focus

Build the workspace, status ledger, config skeleton, and application kernel.
```

Write `docs/status/current-phase.md`:

```md
# Current Phase

- Active phase: Phase 0 transitioning into early Phase 1
- Binary target: `saferunnet`
- Current objective: establish workspace, status tracking, config compatibility skeleton, and app lifecycle skeleton
- Exit gate: `cargo fmt`, `cargo clippy`, and `cargo test` all pass
```

Write `docs/status/modules/app-kernel.md`:

```md
# App Kernel Status

## Purpose

Own startup, shutdown, state transitions, and module orchestration.

## Public Interfaces

- `AppKernel`
- `RuntimeModule`
- `LifecycleState`

## Implemented Items

- none yet

## Partially Implemented Items

- none yet

## Not Yet Implemented

- lifecycle state machine
- module startup/shutdown ordering
- shutdown rollback

## Known Risks

- avoid hidden god-object growth in the kernel

## Test Coverage State

- no tests yet

## Compatibility Notes

- internal runtime boundary only; no direct Lokinet compatibility requirement yet

## Next Recommended Tasks

- add the kernel trait boundary
- add lifecycle tests

## Files and Crates Involved

- `crates/saferunnet-app`
- `crates/saferunnet-core`
```

Write `docs/status/modules/config-system.md`:

```md
# Config System Status

## Purpose

Load Lokinet-style configuration, validate it, and normalize it for internal runtime use.

## Public Interfaces

- `load_from_str`
- `NormalizedConfig`
- `RawLokinetConfig`

## Implemented Items

- none yet

## Partially Implemented Items

- none yet

## Not Yet Implemented

- compatibility parser
- normalization rules
- diagnostics

## Known Risks

- accidental leakage of compatibility-only structures into runtime code

## Test Coverage State

- no tests yet

## Compatibility Notes

- must preserve valuable Lokinet config semantics while improving diagnostics

## Next Recommended Tasks

- build a minimal compatibility parser
- add normalization defaults and errors

## Files and Crates Involved

- `crates/saferunnet-config`
- `crates/saferunnet-compat-lokinet`
```

Write `docs/status/session-log/2026-06-25.md`:

```md
# Session Log 2026-06-25

## What Changed

- approved the rewrite architecture
- created the first implementation plan

## What Did Not Change

- no protocol implementation yet
- no application kernel yet
- no config parser yet

## What Remains Blocked

- nothing; foundation implementation can begin

## What Should Be Done Next

- bootstrap the workspace
- add the status ledger
- implement lifecycle skeleton
- implement config skeleton

## What Was Verified

- the design spec exists
- the implementation plan exists
```

- [ ] **Step 5: Run the layout checks**

Run:

```powershell
./scripts/check-project-layout.ps1
cargo test -p saferunnet-testing required_status_and_script_files_exist
```

Expected: PASS with `Project layout OK` and one passing test.

- [ ] **Step 6: Commit the Phase 0 governance baseline**

Run:

```powershell
git add .
git commit -m "docs: add status ledger and project checks"
```

Expected: PASS with the second commit.

### Task 3: Build the Core Lifecycle Types and the Application Kernel

**Files:**
- Create: `crates/saferunnet-core/src/lifecycle.rs`
- Create: `crates/saferunnet-core/src/module.rs`
- Modify: `crates/saferunnet-core/src/lib.rs`
- Create: `crates/saferunnet-app/src/kernel.rs`
- Modify: `crates/saferunnet-app/src/lib.rs`
- Create: `crates/saferunnet-app/tests/kernel_lifecycle.rs`
- Modify: `docs/status/modules/app-kernel.md`
- Modify: `docs/status/session-log/2026-06-25.md`

- [ ] **Step 1: Write the failing kernel lifecycle tests**

Write `crates/saferunnet-app/tests/kernel_lifecycle.rs`:

```rust
use saferunnet_app::AppKernel;
use saferunnet_core::{LifecycleState, ModuleError, RuntimeModule};
use std::sync::{Arc, Mutex};

struct RecordingModule {
    name: &'static str,
    events: Arc<Mutex<Vec<String>>>,
}

impl RuntimeModule for RecordingModule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        self.events.lock().unwrap().push(format!("start:{}", self.name));
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        self.events.lock().unwrap().push(format!("stop:{}", self.name));
        Ok(())
    }
}

#[test]
fn kernel_starts_and_stops_modules_in_order() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(RecordingModule {
        name: "config",
        events: events.clone(),
    }));
    kernel.register(Box::new(RecordingModule {
        name: "router",
        events: events.clone(),
    }));

    assert_eq!(kernel.state(), LifecycleState::Created);
    kernel.start().unwrap();
    kernel.stop().unwrap();

    assert_eq!(
        events.lock().unwrap().as_slice(),
        ["start:config", "start:router", "stop:router", "stop:config"]
    );
    assert_eq!(kernel.state(), LifecycleState::Stopped);
}

#[test]
fn kernel_rejects_double_start() {
    let mut kernel = AppKernel::new();
    kernel.start().unwrap();
    let error = kernel.start().unwrap_err();
    assert!(error.to_string().contains("cannot start"));
}
```

- [ ] **Step 2: Run the tests to confirm the API is missing**

Run:

```powershell
cargo test -p saferunnet-app kernel_
```

Expected: FAIL with unresolved imports for `AppKernel`, `LifecycleState`, `ModuleError`, or `RuntimeModule`.

- [ ] **Step 3: Implement the lifecycle and module contracts in `saferunnet-core`**

Write `crates/saferunnet-core/src/lifecycle.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Created,
    Starting,
    Running,
    Stopping,
    Stopped,
}
```

Write `crates/saferunnet-core/src/module.rs`:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModuleError {
    #[error("module lifecycle violation: {0}")]
    Lifecycle(String),
}

pub trait RuntimeModule {
    fn name(&self) -> &'static str;
    fn start(&mut self) -> Result<(), ModuleError>;
    fn stop(&mut self) -> Result<(), ModuleError>;
}
```

Replace `crates/saferunnet-core/src/lib.rs` with:

```rust
mod lifecycle;
mod module;

pub use lifecycle::LifecycleState;
pub use module::{ModuleError, RuntimeModule};
```

Update `crates/saferunnet-core/Cargo.toml` to include:

```toml
[dependencies]
thiserror.workspace = true
```

- [ ] **Step 4: Implement the application kernel**

Write `crates/saferunnet-app/src/kernel.rs`:

```rust
use saferunnet_core::{LifecycleState, ModuleError, RuntimeModule};

pub struct AppKernel {
    state: LifecycleState,
    modules: Vec<Box<dyn RuntimeModule>>,
}

impl AppKernel {
    pub fn new() -> Self {
        Self {
            state: LifecycleState::Created,
            modules: Vec::new(),
        }
    }

    pub fn register(&mut self, module: Box<dyn RuntimeModule>) {
        self.modules.push(module);
    }

    pub fn state(&self) -> LifecycleState {
        self.state
    }

    pub fn start(&mut self) -> Result<(), ModuleError> {
        if self.state != LifecycleState::Created && self.state != LifecycleState::Stopped {
            return Err(ModuleError::Lifecycle(format!(
                "cannot start from {:?}",
                self.state
            )));
        }

        self.state = LifecycleState::Starting;
        for module in &mut self.modules {
            module.start()?;
        }
        self.state = LifecycleState::Running;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), ModuleError> {
        if self.state != LifecycleState::Running {
            return Err(ModuleError::Lifecycle(format!(
                "cannot stop from {:?}",
                self.state
            )));
        }

        self.state = LifecycleState::Stopping;
        for module in self.modules.iter_mut().rev() {
            module.stop()?;
        }
        self.state = LifecycleState::Stopped;
        Ok(())
    }
}

impl Default for AppKernel {
    fn default() -> Self {
        Self::new()
    }
}
```

Replace `crates/saferunnet-app/src/lib.rs` with:

```rust
mod kernel;

pub use kernel::AppKernel;
```

- [ ] **Step 5: Run the tests and update the status ledger**

Run:

```powershell
cargo test -p saferunnet-app kernel_
```

Expected: PASS with two passing tests.

Update `docs/status/modules/app-kernel.md` so `Implemented Items` contains:

```md
- lifecycle state machine
- module registration
- startup ordering
- reverse shutdown ordering
```

Update `Test Coverage State` to:

```md
- lifecycle ordering tests pass
- duplicate start protection is covered
```

Append to `docs/status/session-log/2026-06-25.md`:

```md
- implemented the first app kernel lifecycle slice
- verified kernel lifecycle tests
```

- [ ] **Step 6: Commit the kernel slice**

Run:

```powershell
git add .
git commit -m "feat: add app kernel lifecycle skeleton"
```

Expected: PASS with the third commit.

### Task 4: Build the Lokinet Compatibility Parser and Normalized Config Service

**Files:**
- Create: `crates/saferunnet-compat-lokinet/src/parser.rs`
- Modify: `crates/saferunnet-compat-lokinet/src/lib.rs`
- Create: `crates/saferunnet-config/src/model.rs`
- Modify: `crates/saferunnet-config/src/lib.rs`
- Create: `crates/saferunnet-config/tests/config_loading.rs`
- Modify: `docs/status/modules/config-system.md`
- Modify: `docs/status/session-log/2026-06-25.md`

- [ ] **Step 1: Write the failing configuration tests**

Write `crates/saferunnet-config/tests/config_loading.rs`:

```rust
use saferunnet_config::load_from_str;

#[test]
fn load_from_str_normalizes_defaults() {
    let config = load_from_str(
        r#"
        [router]
        nickname=edge-a
        "#,
    )
    .unwrap();

    assert_eq!(config.router.nickname, "edge-a");
    assert_eq!(config.router.data_dir, "./var/lib/saferunnet");
    assert_eq!(config.logging.level, "info");
}

#[test]
fn load_from_str_reports_invalid_lines() {
    let error = load_from_str("nickname=edge-a").unwrap_err();
    assert!(error.to_string().contains("line 1"));
}
```

- [ ] **Step 2: Run the tests to confirm the API is missing**

Run:

```powershell
cargo test -p saferunnet-config load_from_str
```

Expected: FAIL with unresolved import `load_from_str`.

- [ ] **Step 3: Implement the compatibility parser**

Write `crates/saferunnet-compat-lokinet/src/parser.rs`:

```rust
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLokinetConfig {
    pub sections: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("line {line}: key-value pair appears before any section")]
    MissingSection { line: usize },
    #[error("line {line}: invalid entry `{content}`")]
    InvalidEntry { line: usize, content: String },
}

pub fn parse(input: &str) -> Result<RawLokinetConfig, ParseError> {
    let mut sections = BTreeMap::new();
    let mut current_section: Option<String> = None;

    for (index, raw_line) in input.lines().enumerate() {
        let line_no = index + 1;
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let name = line
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .to_string();
            sections.entry(name.clone()).or_insert_with(BTreeMap::new);
            current_section = Some(name);
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(ParseError::InvalidEntry {
                line: line_no,
                content: line.to_string(),
            });
        };

        let Some(section_name) = current_section.clone() else {
            return Err(ParseError::MissingSection { line: line_no });
        };

        sections
            .entry(section_name)
            .or_insert_with(BTreeMap::new)
            .insert(key.trim().to_string(), value.trim().to_string());
    }

    Ok(RawLokinetConfig { sections })
}
```

Replace `crates/saferunnet-compat-lokinet/src/lib.rs` with:

```rust
mod parser;

pub use parser::{parse, ParseError, RawLokinetConfig};
```

- [ ] **Step 4: Implement normalization in `saferunnet-config`**

Write `crates/saferunnet-config/src/model.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterConfig {
    pub nickname: String,
    pub data_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedConfig {
    pub router: RouterConfig,
    pub logging: LoggingConfig,
}
```

Replace `crates/saferunnet-config/src/lib.rs` with:

```rust
mod model;

pub use model::{LoggingConfig, NormalizedConfig, RouterConfig};

use saferunnet_compat_lokinet::{parse, ParseError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("missing required router section")]
    MissingRouterSection,
}

pub fn load_from_str(input: &str) -> Result<NormalizedConfig, ConfigError> {
    let raw = parse(input)?;
    let router = raw
        .sections
        .get("router")
        .ok_or(ConfigError::MissingRouterSection)?;

    let nickname = router
        .get("nickname")
        .cloned()
        .unwrap_or_else(|| "saferunnet-node".to_string());
    let data_dir = router
        .get("data_dir")
        .cloned()
        .unwrap_or_else(|| "./var/lib/saferunnet".to_string());
    let level = raw
        .sections
        .get("logging")
        .and_then(|logging| logging.get("level"))
        .cloned()
        .unwrap_or_else(|| "info".to_string());

    Ok(NormalizedConfig {
        router: RouterConfig { nickname, data_dir },
        logging: LoggingConfig { level },
    })
}
```

- [ ] **Step 5: Run the tests and update the status ledger**

Run:

```powershell
cargo test -p saferunnet-config load_from_str
```

Expected: PASS with two passing tests.

Update `docs/status/modules/config-system.md` so `Implemented Items` contains:

```md
- minimal Lokinet-style section parser
- typed normalized configuration model
- default router and logging values
- actionable line-number parse diagnostics
```

Update `Test Coverage State` to:

```md
- config normalization defaults are covered
- invalid line diagnostics are covered
```

Append to `docs/status/session-log/2026-06-25.md`:

```md
- implemented the config compatibility skeleton
- verified config parser and normalization tests
```

- [ ] **Step 6: Commit the config slice**

Run:

```powershell
git add .
git commit -m "feat: add config compatibility skeleton"
```

Expected: PASS with the fourth commit.

### Task 5: Wire Observability and the `saferunnet` Bootstrap Binary

**Files:**
- Modify: `crates/saferunnet-observability/src/lib.rs`
- Create: `crates/saferunnet-observability/tests/install.rs`
- Modify: `apps/saferunnetd/src/main.rs`
- Create: `apps/saferunnetd/tests/cli.rs`
- Modify: `docs/status/current-phase.md`
- Modify: `docs/status/session-log/2026-06-25.md`

- [ ] **Step 1: Write the failing observability and CLI tests**

Write `crates/saferunnet-observability/tests/install.rs`:

```rust
#[test]
fn install_is_idempotent() {
    saferunnet_observability::install("info").unwrap();
    saferunnet_observability::install("debug").unwrap();
}
```

Write `apps/saferunnetd/tests/cli.rs`:

```rust
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path() -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("saferunnet-{unique}.ini"))
}

#[test]
fn binary_name_is_saferunnet() {
    let output = Command::new(env!("CARGO_BIN_EXE_saferunnet"))
        .output()
        .unwrap();

    assert!(String::from_utf8_lossy(&output.stdout).contains("saferunnet bootstrap ok"));
}

#[test]
fn check_config_accepts_a_minimal_router_section() {
    let path = temp_path();
    fs::write(
        &path,
        "[router]\nnickname=test-node\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_saferunnet"))
        .args(["--check-config", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(String::from_utf8_lossy(&output.stdout).contains("config ok"));
    let _ = fs::remove_file(path);
}
```

- [ ] **Step 2: Run the tests to confirm the features are missing**

Run:

```powershell
cargo test -p saferunnet-observability install_is_idempotent
cargo test -p saferunnetd binary_name_is_saferunnet
```

Expected: FAIL with missing `install` and missing CLI behavior.

- [ ] **Step 3: Implement the observability hook**

Replace `crates/saferunnet-observability/src/lib.rs` with:

```rust
use std::sync::Once;
use thiserror::Error;
use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

#[derive(Debug, Error)]
pub enum ObservabilityError {
    #[error("failed to build log filter: {0}")]
    Filter(String),
}

pub fn install(filter: &str) -> Result<(), ObservabilityError> {
    let filter = EnvFilter::try_new(filter)
        .map_err(|error| ObservabilityError::Filter(error.to_string()))?;

    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .try_init();
    });

    Ok(())
}
```

Update `crates/saferunnet-observability/Cargo.toml` to include:

```toml
[dependencies]
thiserror.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
```

- [ ] **Step 4: Implement the bootstrap binary**

Replace `apps/saferunnetd/src/main.rs` with:

```rust
use saferunnet_config::load_from_str;

fn main() {
    saferunnet_observability::install("info").expect("install tracing");

    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--check-config" {
        let contents = std::fs::read_to_string(&args[2]).expect("read config file");
        load_from_str(&contents).expect("load config");
        println!("config ok");
        return;
    }

    println!("saferunnet bootstrap ok");
}
```

- [ ] **Step 5: Run the tests and update the current phase**

Run:

```powershell
cargo test -p saferunnet-observability install_is_idempotent
cargo test -p saferunnetd
```

Expected: PASS with the observability test and the CLI tests passing.

Update `docs/status/current-phase.md` to:

```md
# Current Phase

- Active phase: Phase 0 complete, early Phase 1 in progress
- Binary target: `saferunnet`
- Current objective: grow the config and app skeleton into richer runtime services
- Exit gate: `cargo fmt`, `cargo clippy`, and `cargo test` all pass
```

Append to `docs/status/session-log/2026-06-25.md`:

```md
- wired the `saferunnet` bootstrap binary
- verified config-check and observability behavior
```

- [ ] **Step 6: Commit the binary wiring**

Run:

```powershell
git add .
git commit -m "feat: wire saferunnet bootstrap binary"
```

Expected: PASS with the fifth commit.

### Task 6: Run the Full Foundation Verification and Finalize Status Records

**Files:**
- Modify: `docs/status/roadmap.md`
- Modify: `docs/status/modules/app-kernel.md`
- Modify: `docs/status/modules/config-system.md`
- Modify: `docs/status/session-log/2026-06-25.md`

- [ ] **Step 1: Update the roadmap and module records to reflect the completed slice**

Update `docs/status/roadmap.md` to:

```md
# Roadmap

- [x] Architecture spec approved
- [x] Phase 0 complete
- [ ] Phase 1 complete
- [ ] Phase 2 complete
- [ ] Phase 3 complete
- [ ] Phase 4 complete
- [ ] Phase 5 complete
- [ ] Phase 6 complete

## Current Focus

Expand the configuration system and app kernel without collapsing module boundaries.
```

Replace the `## Next Recommended Tasks` section in `docs/status/modules/app-kernel.md` with:

```md
## Next Recommended Tasks

- add structured shutdown rollback
- introduce service dependency wiring
- add richer module error categories
```

Replace the `## Next Recommended Tasks` section in `docs/status/modules/config-system.md` with:

```md
## Next Recommended Tasks

- add file-based loading APIs
- add richer validation rules
- add compatibility fixtures from real Lokinet samples
```

Append to `docs/status/session-log/2026-06-25.md`:

```md
- full Phase 0 verification completed
- repository is ready for the next Phase 1 config and kernel expansion tasks
```

- [ ] **Step 2: Run the full verification suite**

Run:

```powershell
./scripts/check.ps1
```

Expected: PASS with:

```text
Project layout OK
All checks passed
```

- [ ] **Step 3: Commit the verified foundation**

Run:

```powershell
git add .
git commit -m "chore: finalize phase 0 foundation status"
```

Expected: PASS with the sixth commit.

- [ ] **Step 4: Record the verification evidence in the session log**

Append to `docs/status/session-log/2026-06-25.md`:

```md
## Verification Commands

- `./scripts/check.ps1`
- `cargo test -p saferunnet-app kernel_`
- `cargo test -p saferunnet-config load_from_str`
- `cargo test -p saferunnetd`

## Verification Result

- all Phase 0 commands passed
- early Phase 1 kernel/config skeleton commands passed
```

Run:

```powershell
git add docs/status/session-log/2026-06-25.md
git commit -m "docs: record phase 0 verification evidence"
```

Expected: PASS with the seventh commit.
