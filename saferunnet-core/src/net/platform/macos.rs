use std::io;
use std::net::IpAddr;
use std::process::Command;

use super::PlatformNetOps;

/// macOS platform networking via `/sbin/route` and `/sbin/ifconfig` commands.
pub struct MacosPlatformNet;

impl PlatformNetOps for MacosPlatformNet {
    fn add_route(&self, dest: IpAddr, prefix_len: u8, _gateway: IpAddr, if_name: &str) -> io::Result<()> {
        let dest_str = format!("{}/{}", dest, prefix_len);
        let output = Command::new("/sbin/route")
            .args(["add", "-net", &dest_str, "-interface", if_name])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(io::ErrorKind::Other, stderr.to_string()));
        }
        Ok(())
    }

    fn del_route(&self, dest: IpAddr, prefix_len: u8, _gateway: IpAddr, if_name: &str) -> io::Result<()> {
        let dest_str = format!("{}/{}", dest, prefix_len);
        let output = Command::new("/sbin/route")
            .args(["delete", "-net", &dest_str, "-interface", if_name])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(io::ErrorKind::Other, stderr.to_string()));
        }
        Ok(())
    }

    fn add_address(&self, addr: IpAddr, prefix_len: u8, if_name: &str) -> io::Result<()> {
        let addr_str = match addr {
            IpAddr::V4(_) => format!("{}/{}", addr, prefix_len),
            IpAddr::V6(_) => format!("{}/{}", addr, prefix_len),
        };
        let family = match addr {
            IpAddr::V4(_) => "inet",
            IpAddr::V6(_) => "inet6",
        };
        let output = Command::new("/sbin/ifconfig")
            .args([if_name, family, &addr_str, "alias"])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(io::ErrorKind::Other, stderr.to_string()));
        }
        Ok(())
    }

    fn del_address(&self, addr: IpAddr, prefix_len: u8, if_name: &str) -> io::Result<()> {
        let addr_str = match addr {
            IpAddr::V4(_) => format!("{}/{}", addr, prefix_len),
            IpAddr::V6(_) => format!("{}/{}", addr, prefix_len),
        };
        let family = match addr {
            IpAddr::V4(_) => "inet",
            IpAddr::V6(_) => "inet6",
        };
        let output = Command::new("/sbin/ifconfig")
            .args([if_name, family, &addr_str, "-alias"])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(io::ErrorKind::Other, stderr.to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_platform_net() {
        let pn = MacosPlatformNet;
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let _ = pn.add_route(addr, 24, addr, "utun3");
        let _ = pn.del_route(addr, 24, addr, "utun3");
    }

    #[test]
    fn test_macos_add_del_address() {
        let pn = MacosPlatformNet;
        let addr: IpAddr = "192.168.1.100".parse().unwrap();
        let _ = pn.add_address(addr, 24, "utun3");
        let _ = pn.del_address(addr, 24, "utun3");
    }
}
