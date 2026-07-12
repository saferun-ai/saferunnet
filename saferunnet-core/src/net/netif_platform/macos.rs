use std::ffi::CStr;
use std::io;
use std::net::IpAddr;

use super::{NetIf, NetifPlatform};

/// macOS network interface enumeration via `getifaddrs()` (libc).
pub struct MacosNetif;

impl NetifPlatform for MacosNetif {
    fn list_interfaces(&self) -> io::Result<Vec<NetIf>> {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let mut interfaces: Vec<NetIf> = Vec::new();
        let mut current = ifap;

        while !current.is_null() {
            unsafe {
                let ifa = &*current;
                let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                let flags = ifa.ifa_flags as i32;

                let iface = match interfaces.iter_mut().find(|i: &&mut NetIf| i.name == name) {
                    Some(iface) => iface,
                    None => {
                        let index = libc::if_nametoindex(ifa.ifa_name);
                        interfaces.push(NetIf {
                            name: name.clone(),
                            index,
                            addresses: Vec::new(),
                            is_up: (flags & libc::IFF_UP as i32) != 0,
                            is_loopback: (flags & libc::IFF_LOOPBACK as i32) != 0,
                        });
                        interfaces.last_mut().unwrap()
                    }
                };

                if !ifa.ifa_addr.is_null() {
                    let sa_family = (*ifa.ifa_addr).sa_family as i32;
                    match sa_family {
                        libc::AF_INET => {
                            let sockaddr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                            let ip = IpAddr::V4(std::net::Ipv4Addr::from(u32::from_ne_bytes(
                                sockaddr.sin_addr.s_addr.to_ne_bytes(),
                            )));
                            let prefix_len = if !ifa.ifa_netmask.is_null() {
                                let nm = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                                32 - u32::from_ne_bytes(nm.sin_addr.s_addr.to_ne_bytes()).trailing_zeros() as u8
                            } else {
                                32
                            };
                            iface.addresses.push((ip, prefix_len));
                        }
                        libc::AF_INET6 => {
                            let sockaddr = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                            let ip = IpAddr::V6(std::net::Ipv6Addr::from(sockaddr.sin6_addr.s6_addr));
                            let prefix_len = if !ifa.ifa_netmask.is_null() {
                                let nm = &*(ifa.ifa_netmask as *const libc::sockaddr_in6);
                                nm.sin6_addr.s6_addr.iter().map(|b| b.count_ones() as u8).sum()
                            } else {
                                128
                            };
                            iface.addresses.push((ip, prefix_len));
                        }
                        _ => {}
                    }
                }

                current = ifa.ifa_next;
            }
        }

        unsafe { libc::freeifaddrs(ifap) };
        Ok(interfaces)
    }

    fn find_by_name(&self, name: &str) -> io::Result<Option<NetIf>> {
        let ifaces = self.list_interfaces()?;
        Ok(ifaces.into_iter().find(|i| i.name == name))
    }

    fn find_by_index(&self, index: u32) -> io::Result<Option<NetIf>> {
        let ifaces = self.list_interfaces()?;
        Ok(ifaces.into_iter().find(|i| i.index == index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_interfaces() {
        let netif = MacosNetif;
        let _ = netif.list_interfaces();
    }

    #[test]
    fn test_find_by_name() {
        let netif = MacosNetif;
        let _ = netif.find_by_name("nonexistent0");
    }
}
