use saferunnet_config::load_from_str;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn temp_path() -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("saferunnet-config-{unique}.ini"))
}

#[test]
fn load_from_file_reads_and_normalizes_config() {
    let path = temp_path();
    fs::write(
        &path,
        r#"
        [router]
        nickname=edge-b
        data_dir=./state

        [logging]
        level=debug
        "#,
    )
    .unwrap();

    let config = saferunnet_config::load_from_file(&path).unwrap();

    assert_eq!(config.router.nickname, "edge-b");
    assert_eq!(config.router.data_dir, "./state");
    assert_eq!(config.logging.level, "debug");

    let _ = fs::remove_file(path);
}

#[test]
fn load_from_str_rejects_blank_router_nickname() {
    let error = load_from_str(
        r#"
        [router]
        nickname=
        "#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("router.nickname"));
}
