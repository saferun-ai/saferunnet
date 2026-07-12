use std::io;
use std::net::IpAddr;
use std::process::Command;

use super::PlatformNetOps;

/// Linux routing via `/sbin/ip route` and `/sbin/ip addr` commands.
pub struct LinuxPlatformNet;

impl PlatformNetOps for LinuxPlatformNet {
    fn add_route(&self, dest: IpAddr, prefix_len: u8, gateway: IpAddr, if_name: &str) -> io::Result<()> {
        let dest_str = match dest {
            IpAddr::V4(_) => format!("{}/{}", dest, prefix_len),
            IpAddr::V6(_) => format!("{}/{}", dest, prefix_len),
        };
        let output = Command::new("/sbin/ip")
            .args(["route", "add", &dest_str, "via", &gateway.to_string(), "dev", if_name])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(io::ErrorKind::Other, stderr.to_string()));
        }
        Ok(())
    }

    fn del_route(&self, dest: IpAddr, prefix_len: u8, gateway: IpAddr, if_name: &str) -> io::Result<()> {
        let dest_str = format!("{}/{}", dest, prefix_len);
        let output = Command::new("/sbin/ip")
            .args(["route", "del", &dest_str, "via", &gateway.to_string(), "dev", if_name])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(io::ErrorKind::Other, stderr.to_string()));
        }
        Ok(())
    }

    fn add_address(&self, addr: IpAddr, prefix_len: u8, if_name: &str) -> io::Result<()> {
        let addr_str = format!("{}/{}", addr, prefix_len);
        let output = Command::new("/sbin/ip")
            .args(["addr", "add", &addr_str, "dev", if_name])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(io::ErrorKind::Other, stderr.to_string()));
        }
        Ok(())
    }

    fn del_address(&self, addr: IpAddr, prefix_len: u8, if_name: &str) -> io::Result<()> {
        let addr_str = format!("{}/{}", addr, prefix_len);
        let output = Command::new("/sbin/ip")
            .args(["addr", "del", &addr_str, "dev", if_name])
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
    fn test_linux_platform_net_commands() {
        let pn = LinuxPlatformNet;
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        // These will fail gracefully without root / iproute2
        let _ = pn.add_route(addr, 24, addr, "eth0");
        let _ = pn.del_route(addr, 24, addr, "eth0");
    }

    #[test]
    fn test_linux_add_del_address() {
        let pn = LinuxPlatformNet;
        let addr: IpAddr = "192.168.1.100".parse().unwrap();
        let _ = pn.add_address(addr, 24, "tun0");
        let _ = pn.del_address(addr, 24, "tun0");
    }
}
