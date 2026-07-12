use std::io;
use std::net::IpAddr;
use std::os::unix::io::{FromRawFd, AsRawFd, RawFd};

use super::TunInterface;

/// Linux TUN interface via `/dev/net/tun` ioctl.
///
/// Opens `/dev/net/tun`, issues `TUNSETIFF` ioctl with `IFF_TUN | IFF_NO_PI`,
/// and sets the fd to non-blocking via `fcntl O_NONBLOCK`.
pub struct LinuxTun {
    name: String,
    file: Option<std::fs::File>,
    mtu: u16,
}

impl LinuxTun {
    const TUNSETIFF: u64 = 0x400454ca;
    const IFF_TUN: i32 = 0x0001;
    const IFF_NO_PI: i32 = 0x1000;
    const IFNAMSIZ: usize = 16;

    /// Returns the raw fd if the device is open.
    pub fn raw_fd(&self) -> Option<RawFd> {
        self.file.as_ref().map(|f| f.as_raw_fd())
    }

    fn create_socket() -> io::Result<std::fs::File> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
}

impl TunInterface for LinuxTun {
    fn open(name: &str) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| io::Error::new(e.kind(), format!("open /dev/net/tun: {}", e)))?;

        let fd = file.as_raw_fd();

        // Build ifreq: name (16 bytes) + flags (2 bytes) = 18 bytes, padded
        let mut ifreq = [0u8; 40];
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(Self::IFNAMSIZ - 1);
        ifreq[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // Set IFF_TUN | IFF_NO_PI flags at offset IFNAMSIZ (16)
        let flags: i16 = (Self::IFF_TUN | Self::IFF_NO_PI) as i16;
        ifreq[Self::IFNAMSIZ..Self::IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());

        let ret = unsafe { libc::ioctl(fd, Self::TUNSETIFF as _, &ifreq as *const _ as _) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Extract actual interface name from ifreq (in case kernel renamed it)
        let nul_pos = ifreq.iter().position(|&b| b == 0).unwrap_or(Self::IFNAMSIZ);
        let actual_name = String::from_utf8_lossy(&ifreq[..nul_pos]).to_string();

        // Set non-blocking
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(LinuxTun {
            name: actual_name,
            file: Some(file),
            mtu: 1500,
        })
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let fd = self.file.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "TUN device not open")
        })?.as_raw_fd();

        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as _, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn write(&self, data: &[u8]) -> io::Result<usize> {
        let fd = self.file.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "TUN device not open")
        })?.as_raw_fd();

        let n = unsafe { libc::write(fd, data.as_ptr() as _, data.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        let sock = Self::create_socket()?;
        let fd = sock.as_raw_fd();

        let mut ifr_mtu = [0u8; 40];
        let name_bytes = self.name.as_bytes();
        let copy_len = name_bytes.len().min(Self::IFNAMSIZ - 1);
        ifr_mtu[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        ifr_mtu[Self::IFNAMSIZ..Self::IFNAMSIZ + 4].copy_from_slice(&(mtu as i32).to_ne_bytes());

        let ret = unsafe { libc::ioctl(fd, libc::SIOCSIFMTU as _, &ifr_mtu as *const _ as _) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_up(&self) -> io::Result<()> {
        let sock = Self::create_socket()?;
        let fd = sock.as_raw_fd();

        // First get current flags
        let mut ifr = [0u8; 40];
        let name_bytes = self.name.as_bytes();
        let copy_len = name_bytes.len().min(Self::IFNAMSIZ - 1);
        ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &ifr as *const _ as _) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Set IFF_UP | IFF_RUNNING
        let current_flags = i16::from_ne_bytes([ifr[Self::IFNAMSIZ], ifr[Self::IFNAMSIZ + 1]]);
        let new_flags = (current_flags as i16 | (libc::IFF_UP | libc::IFF_RUNNING) as i16).to_ne_bytes();
        ifr[Self::IFNAMSIZ] = new_flags[0];
        ifr[Self::IFNAMSIZ + 1] = new_flags[1];

        let ret = unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &ifr as *const _ as _) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_address(&self, addr: IpAddr, prefix_len: u8) -> io::Result<()> {
        let sock = Self::create_socket()?;
        let fd = sock.as_raw_fd();

        match addr {
            IpAddr::V4(ipv4) => {
                let mut ifr = [0u8; 40];
                let name_bytes = self.name.as_bytes();
                let copy_len = name_bytes.len().min(Self::IFNAMSIZ - 1);
                ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

                // sockaddr_in at offset IFNAMSIZ
                let sa_offset = Self::IFNAMSIZ;
                ifr[sa_offset] = libc::AF_INET as u8;
                let octets = ipv4.octets();
                ifr[sa_offset + 2..sa_offset + 6].copy_from_slice(&octets);

                let ret = unsafe { libc::ioctl(fd, libc::SIOCSIFADDR as _, &ifr as *const _ as _) };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }

                // Set netmask
                let mask = if prefix_len == 0 { 0u32 } else { !0u32 << (32 - prefix_len) };
                let mask_octets = u32::to_be(mask).to_ne_bytes();
                ifr[sa_offset] = libc::AF_INET as u8;
                ifr[sa_offset + 2..sa_offset + 6].copy_from_slice(&mask_octets);

                let ret = unsafe { libc::ioctl(fd, libc::SIOCSIFNETMASK as _, &ifr as *const _ as _) };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            IpAddr::V6(_ipv6) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "IPv6 address assignment via ioctl not supported; use `ip addr add`",
                ));
            }
        }

        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        // File is dropped automatically when LinuxTun is dropped
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_linux_tun_stub() {
        // TUN open requires root, so we test struct creation only
        let tun = LinuxTun {
            name: "tun0".into(),
            file: None,
            mtu: 1500,
        };
        assert_eq!(tun.name(), "tun0");
    }

    #[test]
    fn test_set_up_and_mtu_no_fd() {
        let tun = LinuxTun {
            name: "saferunnet0".into(),
            file: None,
            mtu: 1500,
        };
        // Without a real fd, these will fail gracefully
        let _ = tun.set_mtu(1400);
        let _ = tun.set_up();
    }

    #[test]
    fn test_set_address_no_fd() {
        let tun = LinuxTun {
            name: "tun0".into(),
            file: None,
            mtu: 1500,
        };
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let _ = tun.set_address(addr, 24);
    }
}
