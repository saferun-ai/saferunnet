use saferunnet_config::load_from_str;

#[test]
fn parses_bootstrap_routers() {
    let input = "[router]\nnickname=test\nbootstrap=router1.pub,router2.pub\n";
    let config = load_from_str(input).unwrap();
    assert_eq!(
        config.network.bootstrap_routers,
        vec!["router1.pub", "router2.pub"]
    );
}
