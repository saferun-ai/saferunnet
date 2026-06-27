use saferunnet_dns::resolver::{DnsError, is_loki_name, parse_loki_name};

#[test]
fn is_loki_name_accepts_valid_name() {
    assert!(is_loki_name("test.loki"));
    assert!(is_loki_name("a.loki"));
    assert!(is_loki_name("my-service.loki"));
}

#[test]
fn is_loki_name_rejects_non_loki() {
    assert!(!is_loki_name("test.com"));
    assert!(!is_loki_name("test.loki.com"));
    assert!(!is_loki_name("test"));
}

#[test]
fn is_loki_name_rejects_empty_suffix() {
    assert!(!is_loki_name(".loki"));
    assert!(!is_loki_name(""));
}

#[test]
fn parse_loki_name_extracts_host_part() {
    assert_eq!(parse_loki_name("example.loki").unwrap(), "example");
    assert_eq!(parse_loki_name("my-node.loki").unwrap(), "my-node");
    assert_eq!(parse_loki_name("sub.domain.loki").unwrap(), "sub.domain");
}

#[test]
fn parse_loki_name_rejects_non_loki() {
    let err = parse_loki_name("test.com").expect_err("should reject");
    assert!(matches!(err, DnsError::NotLokiName(_)));
}

#[test]
fn parse_loki_name_rejects_dot_loki_only() {
    let err = parse_loki_name(".loki").expect_err("should reject");
    assert!(matches!(err, DnsError::NotLokiName(_)));
}

#[test]
fn parse_loki_name_rejects_invalid_chars() {
    let err = parse_loki_name("bad name.loki").expect_err("should reject");
    assert!(matches!(err, DnsError::InvalidCharacters(_)));
}
