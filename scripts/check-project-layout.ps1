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
