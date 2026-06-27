#[cfg(windows)]
mod wintun_impl {
    use crate::{TunDevice, TunError};
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    /// A real Windows TUN device backed by the wintun driver.
    ///
    /// Requires the wintun.dll driver to be installed or available in the
    /// application directory. See <https://www.wintun.net/>.
    pub struct WinTunDevice {
        /// Keep the wintun DLL loaded for the lifetime of this device.
        _wintun: wintun::Wintun,
        /// The adapter is held to keep it alive; session references it via Arc.
        _adapter: Arc<wintun::Adapter>,
        session: Arc<wintun::Session>,
        mtu: usize,
    }

    impl WinTunDevice {
        /// Create a new Windows TUN adapter.
        ///
        /// * `pool_name` — name of the wintun pool (e.g. "Saferunnet")
        /// * `address` — IPv4 address as a string (e.g. "10.0.0.1")
        /// * `mtu` — maximum transmission unit (typically 1500)
        ///
        /// The driver DLL is loaded automatically via `wintun::load()`.
        /// On failure, the adapter and all resources are cleaned up.
        pub fn create(pool_name: &str, address: &str, mtu: usize) -> Result<Self, TunError> {
            // Load the wintun DLL. This searches standard locations:
            // - current directory, system32, PATH, etc.
            let wintun_lib = unsafe { wintun::load() }
                .map_err(|e| TunError::CreateFailed(format!("failed to load wintun.dll: {e}")))?;

            let adapter = wintun::Adapter::create(&wintun_lib, pool_name, "Saferunnet", None)
                .map_err(|e| TunError::CreateFailed(format!("failed to create adapter: {e}")))?;

            // Set the IP address on the adapter.
            let ip: Ipv4Addr = address
                .parse()
                .map_err(|e| TunError::CreateFailed(format!("invalid address '{address}': {e}")))?;
            adapter
                .set_address(ip)
                .map_err(|e| TunError::CreateFailed(format!("failed to set address: {e}")))?;

            let session = adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| TunError::CreateFailed(format!("failed to start session: {e}")))?;

            Ok(Self {
                _wintun: wintun_lib,
                _adapter: adapter,
                session: Arc::new(session),
                mtu,
            })
        }
    }

    impl TunDevice for WinTunDevice {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
            let packet = self
                .session
                .receive_blocking()
                .map_err(|e| TunError::ReadFailed(e.to_string()))?;
            let bytes = packet.bytes();
            let len = bytes.len().min(buf.len());
            buf[..len].copy_from_slice(&bytes[..len]);
            Ok(len)
        }

        fn write(&mut self, buf: &[u8]) -> Result<usize, TunError> {
            let len = buf.len();
            let len_u16 = u16::try_from(len)
                .map_err(|_| TunError::WriteFailed(format!("packet too large: {len} bytes")))?;
            let mut packet = self
                .session
                .allocate_send_packet(len_u16)
                .map_err(|e| TunError::WriteFailed(e.to_string()))?;
            packet.bytes_mut().copy_from_slice(buf);
            self.session.send_packet(packet);
            Ok(len)
        }

        fn mtu(&self) -> usize {
            self.mtu
        }
    }
}

#[cfg(windows)]
pub use wintun_impl::WinTunDevice;
