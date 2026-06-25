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
