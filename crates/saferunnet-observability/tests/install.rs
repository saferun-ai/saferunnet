#[test]
fn install_is_idempotent() {
    saferunnet_observability::install("info").unwrap();
    saferunnet_observability::install("debug").unwrap();
}
