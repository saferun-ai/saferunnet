use std::net::IpAddr;

/// Network interface abstraction.
/// C++ equivalent: llarp/net/netif.hpp
pub trait NetInterface: Send + Sync {
    fn name(&self) -> &str;
    fn index(&self) -> u32;
    fn addresses(&self) -> Vec<IpAddr>;
    fn is_up(&self) -> bool;
}

/// Returns a list of all network interfaces on the system.
/// Stub — platform implementations will override.
pub fn get_network_interfaces() -> Vec<Box<dyn NetInterface>> {
    Vec::new()
}

/// Find a network interface by name.
/// Stub — platform implementations will override.
pub fn find_interface(name: &str) -> Option<Box<dyn NetInterface>> {
    let _ = name;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockInterface {
        name: String,
        index: u32,
        addresses: Vec<IpAddr>,
        up: bool,
    }

    impl NetInterface for MockInterface {
        fn name(&self) -> &str { &self.name }
        fn index(&self) -> u32 { self.index }
        fn addresses(&self) -> Vec<IpAddr> { self.addresses.clone() }
        fn is_up(&self) -> bool { self.up }
    }

    #[test]
    fn test_mock_interface() {
        let iface = MockInterface {
            name: "eth0".into(),
            index: 1,
            addresses: vec!["10.0.0.1".parse().unwrap()],
            up: true,
        };
        assert_eq!(iface.name(), "eth0");
        assert_eq!(iface.index(), 1);
        assert!(iface.is_up());
        assert_eq!(iface.addresses().len(), 1);
    }

    #[test]
    fn test_get_network_interfaces_stub() {
        let ifaces = get_network_interfaces();
        assert!(ifaces.is_empty());
    }

    #[test]
    fn test_find_interface_stub() {
        assert!(find_interface("eth0").is_none());
    }
}
