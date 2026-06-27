use saferunnet_platform::{StubTunDevice, TunDevice};

#[test]
fn stub_tun_read_returns_zero() {
    let mut tun = StubTunDevice;
    let mut buf = [0u8; 1500];
    assert_eq!(tun.read(&mut buf).unwrap(), 0);
}

#[test]
fn stub_tun_write_returns_zero() {
    let mut tun = StubTunDevice;
    assert_eq!(tun.write(b"hello").unwrap(), 0);
}

#[test]
fn stub_tun_mtu_is_1500() {
    assert_eq!(StubTunDevice.mtu(), 1500);
}

// ---------------------------------------------------------------------------
// Windows TUN device tests — require wintun.dll and administrator privileges.
// Run with: cargo test -p saferunnet-platform -- --ignored
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[cfg(test)]
mod wintun_tests {
    use saferunnet_platform::{TunDevice, WinTunDevice};

    /// Test that we can create and destroy a WinTunDevice.
    /// Requires: administrator privileges + wintun.dll available.
    #[test]
    #[ignore = "requires admin + wintun driver"]
    fn create_wintun_device() {
        let dev = WinTunDevice::create("SaferunnetTest", "10.99.0.1", 1500);
        assert!(dev.is_ok(), "failed to create: {:?}", dev.err());
        let dev = dev.unwrap();
        assert_eq!(dev.mtu(), 1500);
    }

    /// Test read/write roundtrip through the TUN device.
    #[test]
    #[ignore = "requires admin + wintun driver"]
    fn wintun_read_write_roundtrip() {
        let mut dev =
            WinTunDevice::create("SaferunnetTest2", "10.99.0.2", 1400).expect("create device");
        let packet = b"Hello TUN!";
        let written = dev.write(packet).expect("write");
        assert_eq!(written, packet.len());

        let mut buf = [0u8; 2048];
        let read = dev.read(&mut buf).expect("read");
        assert_eq!(read, packet.len());
        assert_eq!(&buf[..read], packet);
    }
}
