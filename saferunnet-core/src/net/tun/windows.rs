use std::io;
use std::net::IpAddr;
use std::process::Command;

use super::TunInterface;

/// Windows TUN interface via netsh (stub for wintun.dll FFI).
///
/// Production builds should use the wintun driver for high-performance
/// ring-buffer I/O. The netsh fallback handles adapter lifecycle.
pub struct WintunInterface {
    name: String,
    adapter_guid: String,
    mtu: u16,
    up: bool,
}

impl WintunInterface {
    fn create_adapter(name: &str) -> io::Result<String> {
        let guid = format!("{{{}}}", name);
        let output = Command::new("netsh")
            .args(["interface", "ip", "add", "address", name, "10.0.0.1", "255.255.255.0"])
            .output();
        match output {
            Ok(_) => Ok(guid),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, format!("netsh failed: {e}"))),
        }
    }
}

impl TunInterface for WintunInterface {
    fn open(name: &str) -> io::Result<Self>
    where
        Self: Sized,
    {
        let guid = Self::create_adapter(name)?;
        Ok(Self { name: name.to_string(), adapter_guid: guid, mtu: 1500, up: false })
    }

    fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0) // stub: real impl uses wintun ring-buffer FFI
    }

    fn write(&self, _data: &[u8]) -> io::Result<usize> {
        Ok(0) // stub: real impl uses wintun ring-buffer FFI
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        let _ = Command::new("netsh")
            .args(["interface", "ipv4", "set", "subinterface", &self.name, "mtu", &mtu.to_string()])
            .output()?;
        Ok(())
    }

    fn set_up(&self) -> io::Result<()> {
        let _ = Command::new("netsh")
            .args(["interface", "set", "interface", &self.name, "admin=enabled"])
            .output()?;
        Ok(())
    }

    fn set_address(&self, addr: IpAddr, prefix_len: u8) -> io::Result<()> {
        let addr_str = match addr {
            IpAddr::V4(v4) => {
                let mask = match prefix_len { 8 => "255.0.0.0", 16 => "255.255.0.0", 24 => "255.255.255.0", _ => "255.255.255.0" };
                format!("{} {}", v4, mask)
            }
            IpAddr::V6(v6) => format!("{}/{}", v6, prefix_len),
        };
        let args = if addr.is_ipv4() {
            vec!["interface", "ip", "add", "address", &self.name]
        } else {
            vec!["interface", "ipv6", "add", "address", &self.name]
        };
        let mut full_args: Vec<&str> = args.into_iter().chain(addr_str.split_whitespace()).collect();
        let _ = Command::new("netsh").args(&full_args).output()?;
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_wintun() {
        let tun = WintunInterface::open("saferunnet").unwrap();
        assert_eq!(tun.name(), "saferunnet");
    }

    #[test]
    fn test_wintun_set_mtu_non_panicking() {
        let iface = WintunInterface {
            name: "saferunnet_test".into(),
            adapter_guid: "{test}".into(),
            mtu: 1500,
            up: false,
        };
        let _ = iface.set_mtu(1400);
    }
}