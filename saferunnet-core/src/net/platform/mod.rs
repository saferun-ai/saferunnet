use std::io;
use std::net::IpAddr;

/// Platform-specific network operations (routes, addresses).
pub trait PlatformNetOps: Send + Sync {
    /// Add an IP route through the given interface.
    fn add_route(&self, dest: IpAddr, prefix_len: u8, gateway: IpAddr, if_name: &str) -> io::Result<()>;
    /// Delete an IP route.
    fn del_route(&self, dest: IpAddr, prefix_len: u8, gateway: IpAddr, if_name: &str) -> io::Result<()>;
    /// Add an IP address to an interface.
    fn add_address(&self, addr: IpAddr, prefix_len: u8, if_name: &str) -> io::Result<()>;
    /// Delete an IP address from an interface.
    fn del_address(&self, addr: IpAddr, prefix_len: u8, if_name: &str) -> io::Result<()>;
}

#[cfg(target_os = "windows")] mod windows;
#[cfg(target_os = "macos")]   mod macos;
#[cfg(target_os = "linux")]   mod linux;

#[cfg(target_os = "windows")] pub use windows::WindowsPlatformNet as PlatformNet;
#[cfg(target_os = "macos")]   pub use macos::MacosPlatformNet as PlatformNet;
#[cfg(target_os = "linux")]   pub use linux::LinuxPlatformNet as PlatformNet;
