use saferunnet_exit::{AllowListPolicy, ExitPolicy, PermitAllPolicy};

#[test]
fn permit_all_allows_anything() {
    let policy = PermitAllPolicy;
    assert!(policy.allows("example.com", 443).is_ok());
    assert!(policy.allows("evil.com", 666).is_ok());
}

#[test]
fn allow_list_rejects_unknown() {
    let policy = AllowListPolicy::new(vec![("example.com".into(), 443)]);
    assert!(policy.allows("example.com", 443).is_ok());
    assert!(policy.allows("evil.com", 80).is_err());
}
