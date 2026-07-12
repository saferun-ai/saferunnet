use std::io;
use std::net::IpAddr;

/// Platform-abstracted TUN interface.
/// Creates a virtual network device for IP-layer packet I/O.
pub trait TunInterface: Send + Sync {
    /// Open/create a TUN device with the given name.
    fn open(name: &str) -> io::Result<Self> where Self: Sized;
    /// Read an IP packet from the TUN device (blocking).
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Write an IP packet to the TUN device.
    fn write(&self, data: &[u8]) -> io::Result<usize>;
    /// Get the device name (e.g. "utun3", "tun0", "saferunnet").
    fn name(&self) -> &str;
    /// Set the MTU.
    fn set_mtu(&self, mtu: u16) -> io::Result<()>;
    /// Bring the interface up.
    fn set_up(&self) -> io::Result<()>;
    /// Assign an IP address to the interface.
    fn set_address(&self, addr: IpAddr, prefix_len: u8) -> io::Result<()>;
    /// Close/destroy the TUN device.
    fn close(&self) -> io::Result<()>;
}

#[cfg(target_os = "windows")] mod windows;
#[cfg(target_os = "macos")]   mod macos;
#[cfg(target_os = "linux")]   mod linux;

#[cfg(target_os = "windows")] pub use windows::WintunInterface as PlatformTun;
#[cfg(target_os = "macos")]   pub use macos::UtunInterface as PlatformTun;
#[cfg(target_os = "linux")]   pub use linux::LinuxTun as PlatformTun;
