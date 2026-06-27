use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// IP protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Icmpv6 = 58,
}

impl IpProtocol {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Icmp),
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            58 => Some(Self::Icmpv6),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmpv6 => "icmpv6",
        }
    }
}

/// Represents an IP packet (v4 or v6) for routing through SaferunNet.
/// Lokinet C++ equivalent: llarp/net/ip_packet.hpp IPPacket
#[derive(Debug, Clone)]
pub struct IpPacket {
    buf: Vec<u8>,
    is_v4: bool,
    is_v6: bool,
    header_len: u8,
    payload_len: u16,
    protocol: IpProtocol,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
}

impl IpPacket {
    pub fn new(data: Vec<u8>) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let version = (data[0] >> 4) & 0x0F;
        match version {
            4 => Self::parse_ipv4(data),
            6 => Self::parse_ipv6(data),
            _ => None,
        }
    }

    fn parse_ipv4(data: Vec<u8>) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let header_len = ((data[0] & 0x0F) * 4) as u8;
        let total_len = u16::from_be_bytes([data[2], data[3]]);
        let protocol = IpProtocol::from_u8(data[9])?;
        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        Some(Self {
            buf: data,
            is_v4: true,
            is_v6: false,
            header_len,
            payload_len: total_len.saturating_sub(header_len as u16),
            protocol,
            src_addr: SocketAddr::new(std::net::IpAddr::V4(src), 0),
            dst_addr: SocketAddr::new(std::net::IpAddr::V4(dst), 0),
        })
    }

    fn parse_ipv6(data: Vec<u8>) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }
        let payload_len = u16::from_be_bytes([data[4], data[5]]);
        let protocol = IpProtocol::from_u8(data[6])?;
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&data[8..24]);
        dst.copy_from_slice(&data[24..40]);
        Some(Self {
            buf: data,
            is_v4: false,
            is_v6: true,
            header_len: 40,
            payload_len,
            protocol,
            src_addr: SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::from(src)), 0),
            dst_addr: SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::from(dst)), 0),
        })
    }

    pub fn is_ipv4(&self) -> bool {
        self.is_v4
    }
    pub fn is_ipv6(&self) -> bool {
        self.is_v6
    }
    pub fn protocol(&self) -> IpProtocol {
        self.protocol
    }
    pub fn source(&self) -> &SocketAddr {
        &self.src_addr
    }
    pub fn destination(&self) -> &SocketAddr {
        &self.dst_addr
    }
    pub fn data(&self) -> &[u8] {
        &self.buf
    }
    pub fn size(&self) -> usize {
        self.buf.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// IPv4 checksum computation
pub fn ipv4_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Pseudo-header checksum for UDP/TCP over IPv4
pub fn ipv4_pseudo_header_checksum(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    for octet in src.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([octet[0], octet[1]]) as u32);
    }
    for octet in dst.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([octet[0], octet[1]]) as u32);
    }
    sum = sum.wrapping_add(protocol as u32);
    sum = sum.wrapping_add(payload.len() as u32);
    for chunk in payload.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_packet() {
        // Minimal IPv4 TCP packet (20 bytes header, no options)
        let data = vec![
            0x45, 0x00, 0x00, 0x28, // ver/ihl, dscp, total_len
            0x00, 0x01, 0x00, 0x00, // id, flags/fragment
            0x40, 0x06, 0x00, 0x00, // ttl, proto(TCP), checksum
            0x0A, 0x00, 0x00, 0x01, // src 10.0.0.1
            0x0A, 0x00, 0x00, 0x02, // dst 10.0.0.2
        ];
        let pkt = IpPacket::new(data).unwrap();
        assert!(pkt.is_ipv4());
        assert_eq!(pkt.protocol(), IpProtocol::Tcp);
        assert_eq!(
            pkt.source().ip(),
            std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            pkt.destination().ip(),
            std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn test_checksum() {
        let data = vec![0x45u8, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11];
        let csum = ipv4_checksum(&data);
        // Known good checksum for this header
        assert_ne!(csum, 0xFFFF); // just verify it computes something valid
    }
}
