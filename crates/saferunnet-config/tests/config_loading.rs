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

fn workspace_root() -> std::path::PathBuf {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
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

#[test]
fn load_from_path_merges_conf_d_files_in_lexical_order() {
    let root = temp_path();
    let conf_d = root.with_extension("d");
    fs::create_dir_all(&conf_d).unwrap();

    fs::write(
        &root,
        r#"
        [router]
        nickname=edge-main
        data_dir=./base
        "#,
    )
    .unwrap();

    fs::write(
        conf_d.join("10-logging.ini"),
        r#"
        [logging]
        level=warn
        "#,
    )
    .unwrap();

    fs::write(
        conf_d.join("20-network.ini"),
        r#"
        [network]
        exit=true
        reachable=1
        ifaddr=10.0.0.1/16
        "#,
    )
    .unwrap();

    fs::write(
        conf_d.join("30-router.ini"),
        r#"
        [router]
        nickname=edge-override
        "#,
    )
    .unwrap();

    let config = saferunnet_config::load_from_path(&root).unwrap();

    assert_eq!(config.router.nickname, "edge-override");
    assert_eq!(config.router.data_dir, "./base");
    assert_eq!(config.logging.level, "warn");
    assert!(config.network.exit);
    assert!(config.network.reachable);

    let _ = fs::remove_dir_all(&conf_d);
    let _ = fs::remove_file(root);
}

#[test]
fn load_from_path_supports_lokinet_style_fixture_layers() {
    let path = workspace_root().join("tests/fixtures/lokinet/client.ini");

    let config = saferunnet_config::load_from_path(&path).unwrap();

    assert_eq!(config.router.nickname, "fixture-client");
    assert_eq!(config.logging.level, "debug");
    assert!(config.network.exit);
    assert!(config.network.reachable);
    assert_eq!(config.network.ifaddr.as_deref(), Some("10.0.0.1/16"));
    assert_eq!(
        config.network.exit_nodes,
        vec!["exit-a.loki".to_string(), "exit-b.loki".to_string()]
    );
    assert_eq!(
        config.network.keyfile.as_deref(),
        Some("lokinet-addr.privkey")
    );
}

#[test]
fn load_from_str_rejects_exit_without_ifaddr() {
    let error = load_from_str(
        r#"
        [router]
        nickname=edge-a

        [network]
        exit=true
        reachable=1
        "#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("network.ifaddr"));
}

#[test]
fn load_from_str_rejects_invalid_ifaddr_shape() {
    let error = load_from_str(
        r#"
        [router]
        nickname=edge-a

        [network]
        ifaddr=10.0.0.1
        "#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("network.ifaddr"));
}

#[test]
fn load_from_str_rejects_zero_hops_or_paths() {
    let error = load_from_str(
        r#"
        [router]
        nickname=edge-a

        [network]
        hops=0
        "#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("network.hops"));

    let error = load_from_str(
        r#"
        [router]
        nickname=edge-a

        [network]
        paths=0
        "#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("network.paths"));
}
