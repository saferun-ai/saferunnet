use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
pub mod dns_platform;
pub mod netif;
pub mod netif_platform;
pub mod platform;
pub mod tun;
/// IP protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol { Icmp = 1, Tcp = 6, Udp = 17, Icmpv6 = 58 }
impl IpProtocol {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v { 1 => Some(Self::Icmp), 6 => Some(Self::Tcp), 17 => Some(Self::Udp), 58 => Some(Self::Icmpv6), _ => None }
    }
    pub fn name(&self) -> &'static str {
        match self { Self::Icmp => "icmp", Self::Tcp => "tcp", Self::Udp => "udp", Self::Icmpv6 => "icmpv6" }
    }
}
/// Represents an IP packet for routing through SaferunNet.
/// Lokinet C++ equivalent: llarp/net/ip_packet.hpp IPPacket
#[derive(Debug, Clone)]
pub struct IpPacket {
    buf: Vec<u8>, is_v4: bool, is_v6: bool,
    header_len: u8, payload_len: u16,
    protocol: IpProtocol,
    src_addr: SocketAddr, dst_addr: SocketAddr,
}
impl IpPacket {
    pub fn new(data: Vec<u8>) -> Option<Self> {
        if data.is_empty() { return None; }
        match (data[0] >> 4) & 0x0F { 4 => Self::parse_ipv4(data), 6 => Self::parse_ipv6(data), _ => None }
    }
    fn parse_ipv4(data: Vec<u8>) -> Option<Self> {
        if data.len() < 20 { return None; }
        let hl = ((data[0] & 0x0F) * 4) as u8;
        let tl = u16::from_be_bytes([data[2], data[3]]);
        let proto = IpProtocol::from_u8(data[9])?;
        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        Some(Self { buf: data, is_v4: true, is_v6: false, header_len: hl, payload_len: tl.saturating_sub(hl as u16), protocol: proto, src_addr: SocketAddr::new(std::net::IpAddr::V4(src), 0), dst_addr: SocketAddr::new(std::net::IpAddr::V4(dst), 0) })
    }
    fn parse_ipv6(data: Vec<u8>) -> Option<Self> {
        if data.len() < 40 { return None; }
        let pl = u16::from_be_bytes([data[4], data[5]]);
        let proto = IpProtocol::from_u8(data[6])?;
        let mut s = [0u8; 16]; let mut d = [0u8; 16];
        s.copy_from_slice(&data[8..24]); d.copy_from_slice(&data[24..40]);
        Some(Self { buf: data, is_v4: false, is_v6: true, header_len: 40, payload_len: pl, protocol: proto, src_addr: SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::from(s)), 0), dst_addr: SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::from(d)), 0) })
    }
    pub fn is_ipv4(&self) -> bool { self.is_v4 }
    pub fn is_ipv6(&self) -> bool { self.is_v6 }
    pub fn protocol(&self) -> IpProtocol { self.protocol }
    pub fn source(&self) -> &SocketAddr { &self.src_addr }
    pub fn destination(&self) -> &SocketAddr { &self.dst_addr }
    pub fn data(&self) -> &[u8] { &self.buf }
    pub fn size(&self) -> usize { self.buf.len() }
    pub fn is_empty(&self) -> bool { self.buf.is_empty() }
    pub fn update_ipv4_address(&mut self, src: Ipv4Addr, dst: Ipv4Addr) {
        if !self.is_v4 || self.buf.len() < 20 { return; }
        self.buf[12..16].copy_from_slice(&src.octets());
        self.buf[16..20].copy_from_slice(&dst.octets());
        self.buf[10] = 0; self.buf[11] = 0;
        let csum = ipv4_checksum(&self.buf[..self.header_len as usize]);
        self.buf[10..12].copy_from_slice(&csum.to_be_bytes());
        self.src_addr = SocketAddr::new(std::net::IpAddr::V4(src), self.src_addr.port());
        self.dst_addr = SocketAddr::new(std::net::IpAddr::V4(dst), self.dst_addr.port());
    }
    pub fn update_ipv6_address(&mut self, src: Ipv6Addr, dst: Ipv6Addr) {
        if !self.is_v6 || self.buf.len() < 40 { return; }
        self.buf[8..24].copy_from_slice(&src.octets());
        self.buf[24..40].copy_from_slice(&dst.octets());
        self.src_addr = SocketAddr::new(std::net::IpAddr::V6(src), self.src_addr.port());
        self.dst_addr = SocketAddr::new(std::net::IpAddr::V6(dst), self.dst_addr.port());
    }
    pub fn source_port(&self) -> u16 { self.src_addr.port() }
    pub fn dest_port(&self) -> u16 { self.dst_addr.port() }
    pub fn udp_data(&self) -> Option<&[u8]> {
        if self.protocol != IpProtocol::Udp { return None; }
        let off = self.header_len as usize + 8;
        if self.buf.len() <= off { return None; }
        Some(&self.buf[off..])
    }
    pub fn into_vec(self) -> Vec<u8> { self.buf }
    pub fn data_mut(&mut self) -> &mut [u8] { &mut self.buf }
}
impl IpPacket {
    pub fn make_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Self> {
        let (s, d) = match (src.ip(), dst.ip()) {
            (std::net::IpAddr::V4(s), std::net::IpAddr::V4(d)) => (s, d),
            _ => return None,
        };
        let ul = 8 + payload.len(); let tl = 20 + ul;
        let mut buf = vec![0u8; tl];
        buf[0] = 0x45; buf[2..4].copy_from_slice(&(tl as u16).to_be_bytes());
        buf[8] = 64; buf[9] = 17;
        buf[12..16].copy_from_slice(&s.octets()); buf[16..20].copy_from_slice(&d.octets());
        let csum = ipv4_checksum(&buf[..20]);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());
        buf[20..22].copy_from_slice(&src.port().to_be_bytes());
        buf[22..24].copy_from_slice(&dst.port().to_be_bytes());
        buf[24..26].copy_from_slice(&(ul as u16).to_be_bytes());
        buf[26..28].copy_from_slice(&[0, 0]);
        buf[28..].copy_from_slice(payload);
        let phc = ipv4_pseudo_header_checksum(s, d, 17, &buf[20..]);
        buf[26..28].copy_from_slice(&phc.to_be_bytes());
        Some(IpPacket { buf, is_v4: true, is_v6: false, header_len: 20, payload_len: tl as u16, protocol: IpProtocol::Udp, src_addr: src, dst_addr: dst })
    }
    pub fn make_icmp_unreachable(&self) -> Option<Self> {
        if !self.is_v4 { return None; }
        let dst = match self.dst_addr.ip() { std::net::IpAddr::V4(ip) => ip, _ => return None };
        let src = match self.src_addr.ip() { std::net::IpAddr::V4(ip) => ip, _ => return None };
        let snip = (self.header_len as usize + 8).min(self.buf.len());
        let icp = 8 + snip; let total = 20 + icp;
        let mut buf = vec![0u8; total];
        buf[0] = 0x45; buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        buf[8] = 64; buf[9] = 1;
        buf[12..16].copy_from_slice(&src.octets()); buf[16..20].copy_from_slice(&dst.octets());
        let hc = ipv4_checksum(&buf[..20]); buf[10..12].copy_from_slice(&hc.to_be_bytes());
        buf[20] = 3; buf[21] = 0;
        buf[28..28+snip].copy_from_slice(&self.buf[..snip]);
        let ic = ipv4_checksum(&buf[20..]); buf[22..24].copy_from_slice(&ic.to_be_bytes());
        Some(IpPacket { buf, is_v4: true, is_v6: false, header_len: 20, payload_len: icp as u16, protocol: IpProtocol::Icmp, src_addr: SocketAddr::new(std::net::IpAddr::V4(src), 0), dst_addr: SocketAddr::new(std::net::IpAddr::V4(dst), 0) })
    }
}
/// IPv4 checksum computation
pub fn ipv4_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 { u16::from_be_bytes([chunk[0], chunk[1]]) as u32 } else { (chunk[0] as u32) << 8 };
        sum = sum.wrapping_add(word);
    }
    while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}
/// Pseudo-header checksum for UDP/TCP over IPv4
pub fn ipv4_pseudo_header_checksum(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for octet in src.octets().chunks(2) { sum = sum.wrapping_add(u16::from_be_bytes([octet[0], octet[1]]) as u32); }
    for octet in dst.octets().chunks(2) { sum = sum.wrapping_add(u16::from_be_bytes([octet[0], octet[1]]) as u32); }
    sum = sum.wrapping_add(protocol as u32); sum = sum.wrapping_add(payload.len() as u32);
    for chunk in payload.chunks(2) {
        let word = if chunk.len() == 2 { u16::from_be_bytes([chunk[0], chunk[1]]) as u32 } else { (chunk[0] as u32) << 8 };
        sum = sum.wrapping_add(word);
    }
    while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}
/// IPv4 CIDR range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRange { pub addr: Ipv4Addr, pub prefix_len: u8 }
impl IpRange {
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Self { Self { addr, prefix_len } }
    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        if self.prefix_len == 0 { return true; }
        let mask = u32::MAX.wrapping_shl(32 - self.prefix_len as u32);
        (u32::from(self.addr) & mask) == (u32::from(*ip) & mask)
    }
}
/// IPv6 CIDR range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Range { pub addr: Ipv6Addr, pub prefix_len: u8 }
impl Ipv6Range {
    pub fn new(addr: Ipv6Addr, prefix_len: u8) -> Self { Self { addr, prefix_len } }
    pub fn contains(&self, ip: &Ipv6Addr) -> bool {
        if self.prefix_len == 0 { return true; }
        if self.prefix_len > 128 { return false; }
        let mask = u128::MAX.wrapping_shl(128 - self.prefix_len as u32);
        (u128::from(self.addr) & mask) == (u128::from(*ip) & mask)
    }
}
/// Maximum IP packet size (standard Ethernet MTU).
pub const MAX_PACKET_SIZE: usize = 1500;
/// Minimum IP packet size (IPv4 header without options).
pub const MIN_PACKET_SIZE: usize = 20;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_ipv4_packet() {
        let data = vec![0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x02];
        let pkt = IpPacket::new(data).unwrap();
        assert!(pkt.is_ipv4()); assert_eq!(pkt.protocol(), IpProtocol::Tcp);
        assert_eq!(pkt.source().ip(), std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }
    #[test]
    fn test_checksum() {
        let data = vec![0x45u8, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11];
        assert_ne!(ipv4_checksum(&data), 0xFFFF);
    }
    #[test]
    fn test_update_ipv4_address() {
        let data = vec![0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x02];
        let mut pkt = IpPacket::new(data).unwrap();
        pkt.update_ipv4_address(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(pkt.source().ip(), std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }
    #[test]
    fn test_make_udp_packet() {
        let src: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let dst: SocketAddr = "10.0.0.2:9090".parse().unwrap();
        let pkt = IpPacket::make_udp_packet(src, dst, b"hello").unwrap();
        assert!(pkt.is_ipv4()); assert_eq!(pkt.protocol(), IpProtocol::Udp);
        assert_eq!(pkt.udp_data().unwrap(), b"hello");
    }
    #[test]
    fn test_make_icmp_unreachable() {
        let data = vec![0x45, 0x00, 0x00, 0x28, 0, 0, 0, 0, 0x40, 0x11, 0, 0, 0x0A, 0, 0, 1, 0x0A, 0, 0, 2];
        let pkt = IpPacket::new(data).unwrap();
        let icmp = pkt.make_icmp_unreachable().unwrap();
        assert_eq!(icmp.protocol(), IpProtocol::Icmp);
    }
    #[test]
    fn test_ip_range_contains() {
        let range = IpRange::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        assert!(range.contains(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!range.contains(&Ipv4Addr::new(10, 0, 1, 1)));
    }
    #[test]
    fn test_into_vec() {
        let data = vec![0x45u8, 0, 0, 0x28, 0, 0, 0, 0, 0x40, 0x06, 0, 0, 0x0A, 0, 0, 1, 0x0A, 0, 0, 2];
        let pkt = IpPacket::new(data.clone()).unwrap();
        assert_eq!(pkt.into_vec(), data);
    }
    #[test]
    fn test_ipv6_range_contains() {
        let range = Ipv6Range::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 16);
        assert!(range.contains(&Ipv6Addr::new(0xfd00, 0x1234, 0, 0, 0, 0, 0, 1)));
        assert!(!range.contains(&Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)));
    }
    #[test]
    fn test_max_packet_size_gt_min() {
        assert!(MAX_PACKET_SIZE > MIN_PACKET_SIZE);
    }
}
