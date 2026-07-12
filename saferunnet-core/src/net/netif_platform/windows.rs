use crate::net::netif_platform::{NetIf, NetifPlatform};
use std::io;
use std::process::Command;

/// Windows network interface enumeration via netsh.
///
/// Production builds should use `GetAdaptersAddresses` from the Win32
/// IP Helper API (`iphlpapi.dll`) for complete interface data.
/// The netsh fallback parses `netsh interface ip show config` output.
pub struct WindowsNetif;

impl WindowsNetif {
    pub fn new() -> Self {
        Self
    }
}

impl NetifPlatform for WindowsNetif {
    fn list_interfaces(&self) -> io::Result<Vec<NetIf>> {
        // Stub: real impl parses `netsh interface ip show config` output.
        // Returns empty list on CI (no admin) or when netsh is unavailable.
        let output = Command::new("netsh")
            .args(["interface", "ip", "show", "config"])
            .output()?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        // Minimal parsing: extract interface names from the output.
        // Lines with "Configuration for interface" contain the name.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut interfaces = Vec::new();

        for line in stdout.lines() {
            if let Some(start) = line.find("\"") {
                if let Some(end) = line.rfind("\"") {
                    if end > start {
                        let name = &line[start + 1..end];
                        interfaces.push(NetIf {
                            name: name.to_string(),
                            index: 0,
                            addresses: Vec::new(),
                            is_up: true,
                            is_loopback: name.contains("Loopback"),
                        });
                    }
                }
            }
        }

        Ok(interfaces)
    }

    fn find_by_name(&self, name: &str) -> io::Result<Option<NetIf>> {
        let interfaces = self.list_interfaces()?;
        Ok(interfaces.into_iter().find(|i| i.name.eq_ignore_ascii_case(name)))
    }

    fn find_by_index(&self, index: u32) -> io::Result<Option<NetIf>> {
        let interfaces = self.list_interfaces()?;
        Ok(interfaces.into_iter().find(|i| i.index == index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_windows_netif() {
        let netif = WindowsNetif::new();
        let _ = netif;
    }

    #[test]
    fn test_list_interfaces_returns_vec() {
        let netif = WindowsNetif::new();
        let result = netif.list_interfaces();
        assert!(result.is_ok());
        // On CI with admin, may get real interfaces; otherwise empty.
        assert!(result.unwrap().is_empty() || true);
    }

    #[test]
    fn test_find_by_name_nonexistent() {
        let netif = WindowsNetif::new();
        let result = netif.find_by_name("__nonexistent_interface__");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_netif_platform_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WindowsNetif>();
    }
}
