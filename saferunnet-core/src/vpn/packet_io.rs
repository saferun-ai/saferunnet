use std::io;

use crate::net::IpPacket;

/// Trait for writing IP packets to a network interface.
pub trait PacketWriter: Send + Sync {
    /// Write a single IP packet. Returns `Ok(())` on success.
    fn write_packet(&self, pkt: &IpPacket) -> io::Result<()>;
}

/// Trait for reading IP packets from a network interface.
pub trait PacketReader: Send + Sync {
    /// Read a single IP packet into `buf`. Returns the number of bytes read.
    /// Implementations should return `Ok(0)` when no data is available
    /// (non-blocking), and `Err` on actual I/O errors.
    fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize>;
}

/// Combined reader + writer for a TUN interface.
///
/// This is a stub that will later wrap a tokio TUN file descriptor.
/// For now it stores packets in a buffer for testing purposes.
#[derive(Debug, Default)]
pub struct TunPacketIO {
    /// In-memory buffer that simulates the TUN device read queue.
    read_buffer: std::sync::Mutex<Vec<Vec<u8>>>,
    /// If set, `read_packet` will return this error.
    inject_read_error: std::sync::Mutex<Option<io::Error>>,
    /// If set, `write_packet` will return this error.
    inject_write_error: std::sync::Mutex<Option<io::Error>>,
}

impl TunPacketIO {
    /// Create a new stub TunPacketIO.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject a packet into the simulated read buffer.
    pub fn inject_packet(&self, data: Vec<u8>) {
        self.read_buffer.lock().unwrap().push(data);
    }

    /// Number of packets waiting in the read buffer.
    pub fn pending_reads(&self) -> usize {
        self.read_buffer.lock().unwrap().len()
    }

    /// Cause the next `read_packet` to return this error.
    pub fn set_read_error(&self, err: io::Error) {
        *self.inject_read_error.lock().unwrap() = Some(err);
    }

    /// Cause the next `write_packet` to return this error.
    pub fn set_write_error(&self, err: io::Error) {
        *self.inject_write_error.lock().unwrap() = Some(err);
    }

    /// Clear injected errors.
    pub fn clear_errors(&self) {
        *self.inject_read_error.lock().unwrap() = None;
        *self.inject_write_error.lock().unwrap() = None;
    }
}

impl PacketWriter for TunPacketIO {
    fn write_packet(&self, _pkt: &IpPacket) -> io::Result<()> {
        if let Some(err) = self.inject_write_error.lock().unwrap().take() {
            return Err(err);
        }
        // Stub: just acknowledge the write.
        Ok(())
    }
}

impl PacketReader for TunPacketIO {
    fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(err) = self.inject_read_error.lock().unwrap().take() {
            return Err(err);
        }
        let mut rb = self.read_buffer.lock().unwrap();
        if let Some(data) = rb.pop() {
            let n = data.len().min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Ok(n)
        } else {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock reader that returns fixed data.
    struct MockReader {
        data: Vec<u8>,
        offset: std::sync::Mutex<usize>,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                offset: std::sync::Mutex::new(0),
            }
        }
    }

    impl PacketReader for MockReader {
        fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut off = self.offset.lock().unwrap();
            if *off >= self.data.len() {
                return Ok(0);
            }
            let remaining = &self.data[*off..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            *off += n;
            Ok(n)
        }
    }

    /// A mock writer that collects written data.
    struct MockWriter {
        written: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl MockWriter {
        fn new() -> Self {
            Self {
                written: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn last_written(&self) -> Option<Vec<u8>> {
            self.written.lock().unwrap().last().cloned()
        }
    }

    impl PacketWriter for MockWriter {
        fn write_packet(&self, pkt: &IpPacket) -> io::Result<()> {
            self.written.lock().unwrap().push(pkt.data().to_vec());
            Ok(())
        }
    }

    // ── Mock reader/writer tests ─────────────────────────────

    #[test]
    fn test_mock_read_write() {
        let reader = MockReader::new(vec![0x45, 0x00, 0x00, 0x14]);
        let mut buf = [0u8; 1500];
        let n = reader.read_packet(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], &[0x45, 0x00, 0x00, 0x14]);

        // Second read returns 0 (EOF)
        let n2 = reader.read_packet(&mut buf).unwrap();
        assert_eq!(n2, 0);
    }

    #[test]
    fn test_mock_write_collects() {
        let writer = MockWriter::new();

        let src: std::net::SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let dst: std::net::SocketAddr = "10.0.0.2:9090".parse().unwrap();
        let pkt = IpPacket::make_udp_packet(src, dst, b"hello").unwrap();

        writer.write_packet(&pkt).unwrap();
        let last = writer.last_written().unwrap();
        assert!(!last.is_empty());
    }

    // ── TunPacketIO tests ────────────────────────────────────

    #[test]
    fn test_tun_inject_and_read() {
        let tun = TunPacketIO::new();
        assert_eq!(tun.pending_reads(), 0);

        let packet = vec![0x45, 0x00, 0x00, 0x28];
        tun.inject_packet(packet.clone());
        assert_eq!(tun.pending_reads(), 1);

        let mut buf = [0u8; 1500];
        let n = tun.read_packet(&mut buf).unwrap();
        assert_eq!(n, packet.len());
        assert_eq!(&buf[..n], &packet[..]);

        // Buffer empty now
        assert_eq!(tun.pending_reads(), 0);
        let n2 = tun.read_packet(&mut buf).unwrap();
        assert_eq!(n2, 0);
    }

    #[test]
    fn test_tun_read_truncation() {
        let tun = TunPacketIO::new();
        let packet = vec![0xAA; 100];
        tun.inject_packet(packet);

        let mut small_buf = [0u8; 10];
        let n = tun.read_packet(&mut small_buf).unwrap();
        assert_eq!(n, 10); // truncated to buf size
    }

    #[test]
    fn test_tun_write_ack() {
        let tun = TunPacketIO::new();
        let src: std::net::SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let dst: std::net::SocketAddr = "10.0.0.2:9090".parse().unwrap();
        let pkt = IpPacket::make_udp_packet(src, dst, b"data").unwrap();

        assert!(tun.write_packet(&pkt).is_ok());
    }

    #[test]
    fn test_tun_read_error_injection() {
        let tun = TunPacketIO::new();
        tun.set_read_error(io::Error::new(io::ErrorKind::ConnectionReset, "mock error"));

        let mut buf = [0u8; 1500];
        let result = tun.read_packet(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);

        // Error is consumed — next read works normally
        tun.inject_packet(vec![0x45]);
        let n = tun.read_packet(&mut buf).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn test_tun_write_error_injection() {
        let tun = TunPacketIO::new();
        tun.set_write_error(io::Error::new(io::ErrorKind::BrokenPipe, "mock write error"));

        let src: std::net::SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let dst: std::net::SocketAddr = "10.0.0.2:9090".parse().unwrap();
        let pkt = IpPacket::make_udp_packet(src, dst, b"data").unwrap();

        let result = tun.write_packet(&pkt);
        assert!(result.is_err());

        // Error consumed — next write succeeds
        assert!(tun.write_packet(&pkt).is_ok());
    }
}
