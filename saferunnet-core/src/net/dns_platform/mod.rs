use std::io;
use std::net::SocketAddr;

/// Platform-specific DNS configuration.
pub trait DnsPlatform: Send + Sync {
    /// Set the system DNS server(s) for the TUN interface.
    fn set_dns(&self, servers: &[SocketAddr], if_name: &str) -> io::Result<()>;
    /// Remove DNS configuration.
    fn remove_dns(&self, if_name: &str) -> io::Result<()>;
    /// Add a search domain for the TUN interface.
    fn add_search_domain(&self, domain: &str, if_name: &str) -> io::Result<()>;
}

#[cfg(target_os = "windows")] mod windows;
#[cfg(target_os = "macos")]   mod macos;
#[cfg(target_os = "linux")]   mod linux;

#[cfg(target_os = "windows")] pub use windows::WindowsDns as PlatformDns;
#[cfg(target_os = "macos")]   pub use macos::MacosDns as PlatformDns;
#[cfg(target_os = "linux")]   pub use linux::LinuxDns as PlatformDns;
