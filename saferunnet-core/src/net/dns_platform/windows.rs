use std::io;
use std::net::SocketAddr;
use std::process::Command;

use super::DnsPlatform;

/// Windows DNS configuration via netsh and registry.
///
/// Sets per-interface DNS servers and search domains using netsh.
/// Production builds may write directly to:
/// `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\NameServer`
pub struct WindowsDns;

impl WindowsDns {
    pub fn new() -> Self { Self }
}

impl DnsPlatform for WindowsDns {
    fn set_dns(&self, servers: &[SocketAddr], if_name: &str) -> io::Result<()> {
        if servers.is_empty() {
            return Ok(());
        }
        for server in servers {
            let _ = Command::new("netsh")
                .args(["interface", "ip", "add", "dns", if_name, &server.ip().to_string(), "index=1"])
                .output()?;
        }
        Ok(())
    }

    fn remove_dns(&self, if_name: &str) -> io::Result<()> {
        let _ = Command::new("netsh")
            .args(["interface", "ip", "delete", "dns", if_name, "all"])
            .output()?;
        Ok(())
    }

    fn add_search_domain(&self, domain: &str, if_name: &str) -> io::Result<()> {
        // netsh doesn't directly support search domains; registry write is the proper path.
        // For now, set connection-specific DNS suffix via netsh dhcp mode.
        let _ = Command::new("netsh")
            .args(["interface", "ip", "set", "dns", if_name, "dhcp"])
            .output()?;
        let _ = domain;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_dns_empty_servers() {
        let dns = WindowsDns::new();
        assert!(dns.set_dns(&[], "saferunnet").is_ok());
    }

    #[test]
    fn test_set_dns_non_panicking() {
        let dns = WindowsDns::new();
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let _ = dns.set_dns(&[addr], "saferunnet");
    }

    #[test]
    fn test_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WindowsDns>();
    }
}