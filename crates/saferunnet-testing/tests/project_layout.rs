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
