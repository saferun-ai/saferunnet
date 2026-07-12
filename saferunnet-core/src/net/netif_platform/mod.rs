use std::io;
use std::net::IpAddr;

/// A single network interface.
pub struct NetIf {
    pub name: String,
    pub index: u32,
    pub addresses: Vec<(IpAddr, u8)>,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// Platform-specific network interface enumeration.
pub trait NetifPlatform: Send + Sync {
    /// List all network interfaces.
    fn list_interfaces(&self) -> io::Result<Vec<NetIf>>;
    /// Find an interface by name.
    fn find_by_name(&self, name: &str) -> io::Result<Option<NetIf>>;
    /// Find an interface by index.
    fn find_by_index(&self, index: u32) -> io::Result<Option<NetIf>>;
}

#[cfg(target_os = "windows")] mod windows;
#[cfg(target_os = "macos")]   mod macos;
#[cfg(target_os = "linux")]   mod linux;

#[cfg(target_os = "windows")] pub use windows::WindowsNetif as PlatformNetif;
#[cfg(target_os = "macos")]   pub use macos::MacosNetif as PlatformNetif;
#[cfg(target_os = "linux")]   pub use linux::LinuxNetif as PlatformNetif;
