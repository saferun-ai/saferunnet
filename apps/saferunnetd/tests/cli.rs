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
    fs::write(&path, "[router]\nnickname=test-node\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_saferunnet"))
        .args(["--check-config", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(String::from_utf8_lossy(&output.stdout).contains("config ok"));
    let _ = fs::remove_file(path);
}
