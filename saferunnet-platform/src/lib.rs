pub mod tun;
pub use tun::{StubTunDevice, TunDevice, TunError};

#[cfg(windows)]
pub mod wintun;
#[cfg(windows)]
pub use wintun::WinTunDevice;
