use std::ffi::CStr;
use std::io;
use std::net::IpAddr;
use std::os::unix::io::{FromRawFd, AsRawFd, RawFd};

use super::TunInterface;

/// macOS TUN interface via utun (socket `AF_SYSTEM + SYSPROTO_CONTROL + CTLIOCGINFO`).
pub struct UtunInterface {
    name: String,
    file: Option<std::fs::File>,
    mtu: u16,
}

// macOS-specific constants
const SYSPROTO_CONTROL: i32 = 2;
const AF_SYS_CONTROL: u8 = 2;
const UTUN_OPT_IFNAME: i32 = 2;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
const CTLIOCGINFO: u64 = 0xc0644e03;
const IFNAMSIZ: usize = 16;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

impl SockaddrCtl {
    fn new(ctl_id: u32, unit: u32) -> Self {
        SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL as u16,
            sc_id: ctl_id,
            sc_unit: unit,
            sc_reserved: [0u32; 5],
        }
    }
}

impl UtunInterface {
    fn create_socket() -> io::Result<std::fs::File> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    /// Find the control ID for the utun kernel extension.
    fn get_utun_ctl_id(ctl_fd: RawFd) -> io::Result<u32> {
        let mut ctl_info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0u8; 96],
        };
        ctl_info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);

        let ret = unsafe {
            libc::ioctl(ctl_fd, CTLIOCGINFO as _, &mut ctl_info as *mut _ as _)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ctl_info.ctl_id)
    }
}

impl TunInterface for UtunInterface {
    fn open(name: &str) -> io::Result<Self> {
        // Create AF_SYSTEM socket
        let ctl_fd = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if ctl_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Find utun control ID
        let ctl_id = Self::get_utun_ctl_id(ctl_fd)?;

        // Connect to utun with auto-assigned unit (sc_unit = 0)
        let addr = SockaddrCtl::new(ctl_id, 0);
        let ret = unsafe {
            libc::connect(
                ctl_fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe { libc::close(ctl_fd) };
            return Err(io::Error::last_os_error());
        }

        // Retrieve assigned interface name
        let mut ifname = [0u8; IFNAMSIZ];
        let mut ifname_len = IFNAMSIZ as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                ctl_fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                ifname.as_mut_ptr() as _,
                &mut ifname_len,
            )
        };
        let actual_name = if ret < 0 {
            // Fallback: use the requested name
            name.to_string()
        } else {
            let nul = ifname.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
            String::from_utf8_lossy(&ifname[..nul]).to_string()
        };

        // Set non-blocking
        let flags = unsafe { libc::fcntl(ctl_fd, libc::F_GETFL, 0) };
        if flags < 0 {
            unsafe { libc::close(ctl_fd) };
            return Err(io::Error::last_os_error());
        }
        let ret = unsafe { libc::fcntl(ctl_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            unsafe { libc::close(ctl_fd) };
            return Err(io::Error::last_os_error());
        }

        Ok(UtunInterface {
            name: actual_name,
            file: Some(unsafe { std::fs::File::from_raw_fd(ctl_fd) }),
            mtu: 1500,
        })
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let fd = self.file.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "utun device not open")
        })?.as_raw_fd();

        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as _, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // macOS utun prepends 4-byte protocol family header; skip it
        let skip = 4;
        if n <= skip {
            return Ok(0);
        }
        let payload_len = (n - skip) as usize;
        buf.copy_within(skip as usize..n as usize, 0);
        Ok(payload_len)
    }

    fn write(&self, data: &[u8]) -> io::Result<usize> {
        let fd = self.file.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "utun device not open")
        })?.as_raw_fd();

        // macOS utun expects 4-byte protocol family prefix (AF_INET = 2)
        let af: u32 = (libc::AF_INET as u32).to_be();
        let mut pkt = Vec::with_capacity(4 + data.len());
        pkt.extend_from_slice(&af.to_ne_bytes());
        pkt.extend_from_slice(data);

        let n = unsafe { libc::write(fd, pkt.as_ptr() as _, pkt.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(data.len()) // Return user data length, not including header
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        let sock = Self::create_socket()?;
        let fd = sock.as_raw_fd();

        let mut ifr_mtu = [0u8; 40];
        let name_bytes = self.name.as_bytes();
        let copy_len = name_bytes.len().min(IFNAMSIZ - 1);
        ifr_mtu[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        ifr_mtu[IFNAMSIZ..IFNAMSIZ + 4].copy_from_slice(&(mtu as i32).to_ne_bytes());

        let ret = unsafe { libc::ioctl(fd, libc::SIOCSIFMTU as _, &ifr_mtu as *const _ as _) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_up(&self) -> io::Result<()> {
        let sock = Self::create_socket()?;
        let fd = sock.as_raw_fd();

        let mut ifr = [0u8; 40];
        let name_bytes = self.name.as_bytes();
        let copy_len = name_bytes.len().min(IFNAMSIZ - 1);
        ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &ifr as *const _ as _) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let current_flags = i16::from_ne_bytes([ifr[IFNAMSIZ], ifr[IFNAMSIZ + 1]]);
        let new_flags = (current_flags | (libc::IFF_UP | libc::IFF_RUNNING) as i16).to_ne_bytes();
        ifr[IFNAMSIZ] = new_flags[0];
        ifr[IFNAMSIZ + 1] = new_flags[1];

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
                let copy_len = name_bytes.len().min(IFNAMSIZ - 1);
                ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

                let sa_offset = IFNAMSIZ;
                ifr[sa_offset] = libc::AF_INET as u8;
                let octets = ipv4.octets();
                ifr[sa_offset + 2..sa_offset + 6].copy_from_slice(&octets);

                let ret = unsafe { libc::ioctl(fd, libc::SIOCSIFADDR as _, &ifr as *const _ as _) };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }

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
                // macOS auto-assigns link-local IPv6; for global IPv6 use ifconfig
                let output = std::process::Command::new("/sbin/ifconfig")
                    .args([&self.name, "inet6", &format!("{}/{}", _ipv6, prefix_len), "alias"])
                    .output()?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(io::Error::new(io::ErrorKind::Other, stderr.to_string()));
                }
            }
        }

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
    fn test_create_utun_stub() {
        let tun = UtunInterface {
            name: "utun3".into(),
            file: None,
            mtu: 1500,
        };
        assert_eq!(tun.name(), "utun3");
    }

    #[test]
    fn test_utun_read_write_no_fd() {
        let tun = UtunInterface {
            name: "utun3".into(),
            file: None,
            mtu: 1500,
        };
        let mut buf = [0u8; 1500];
        assert!(tun.read(&mut buf).is_err());
        assert!(tun.write(&[0u8; 100]).is_err());
    }
}
