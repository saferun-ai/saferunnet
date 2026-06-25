use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path() -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("saferunnet-{unique}.ini"))
}

fn temp_dir() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("saferunnet-cli-{unique}"))
}

#[test]
fn binary_name_is_saferunnet() {
    let output = Command::new(env!("CARGO_BIN_EXE_saferunnet"))
        .output()
        .unwrap();

    assert!(output.status.success());
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

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("config ok"));
    let _ = fs::remove_file(path);
}

#[test]
fn bootstrap_resolves_relative_keyfile_under_relative_data_dir() {
    let root = temp_dir();
    let config_path = root.join("config").join("saferunnet.ini");
    let expected_keyfile = root
        .join("config")
        .join("state")
        .join("keys")
        .join("node.key");
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::write(
        &config_path,
        "[router]\nnickname=bootstrap-node\ndata_dir=state\n[network]\nkeyfile=keys/node.key\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_saferunnet"))
        .args(["--bootstrap", config_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("identity bootstrap ok"));
    assert!(expected_keyfile.exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn bootstrap_defaults_keyfile_under_data_dir_and_creates_parent_dirs() {
    let root = temp_dir();
    let config_path = root.join("config").join("saferunnet.ini");
    let expected_keyfile = root.join("config").join("fresh-state").join("identity.key");
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::write(
        &config_path,
        "[router]\nnickname=bootstrap-node\ndata_dir=fresh-state\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_saferunnet"))
        .args(["--bootstrap", config_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("identity bootstrap ok"));
    assert!(expected_keyfile.exists());

    let _ = fs::remove_dir_all(root);
}
