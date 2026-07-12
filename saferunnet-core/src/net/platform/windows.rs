use std::io;
use std::net::IpAddr;
use std::process::Command;

use super::PlatformNetOps;

/// Windows platform network operations via netsh.
///
/// Production builds should replace netsh with direct Win32 API calls
/// (`CreateIpForwardEntry`, `AddIPAddress`, etc from iphlpapi.dll).
pub struct WindowsPlatformNet;

impl WindowsPlatformNet {
    pub fn new() -> Self { Self }
}

impl PlatformNetOps for WindowsPlatformNet {
    fn add_route(&self, dest: IpAddr, prefix_len: u8, gateway: IpAddr, if_name: &str) -> io::Result<()> {
        let dest_str = format!("{}/{}", dest, prefix_len);
        let _ = Command::new("netsh")
            .args(["interface", "ip", "add", "route", &dest_str, if_name, &gateway.to_string()])
            .output()?;
        Ok(())
    }

    fn del_route(&self, dest: IpAddr, prefix_len: u8, _gateway: IpAddr, if_name: &str) -> io::Result<()> {
        let dest_str = format!("{}/{}", dest, prefix_len);
        let _ = Command::new("netsh")
            .args(["interface", "ip", "delete", "route", &dest_str, if_name])
            .output()?;
        Ok(())
    }

    fn add_address(&self, addr: IpAddr, prefix_len: u8, if_name: &str) -> io::Result<()> {
        let mask = match addr {
            IpAddr::V4(_) => {
                let m = u32::MAX.checked_shl(32u32.saturating_sub(prefix_len as u32)).unwrap_or(0);
                format!("{}.{}.{}.{}", (m>>24) as u8, (m>>16) as u8, (m>>8) as u8, m as u8)
            }
            IpAddr::V6(_) => prefix_len.to_string(),
        };
        let _ = Command::new("netsh")
            .args(["interface", "ip", "add", "address", if_name, &addr.to_string(), &mask])
            .output()?;
        Ok(())
    }

    fn del_address(&self, addr: IpAddr, _prefix_len: u8, if_name: &str) -> io::Result<()> {
        let _ = Command::new("netsh")
            .args(["interface", "ip", "delete", "address", if_name, "addr=", &addr.to_string()])
            .output()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_windows_platform_net() {
        let pn = WindowsPlatformNet::new();
        let _ = pn;
    }

    #[test]
    fn test_add_route_non_panicking() {
        let pn = WindowsPlatformNet::new();
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let _ = pn.add_route(addr, 24, addr, "saferunnet");
    }

    #[test]
    fn test_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WindowsPlatformNet>();
    }
}