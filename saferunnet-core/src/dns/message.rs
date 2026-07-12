//! DNS wire-format message encoding and decoding.
//! Lokinet C++ equivalent: llarp/dns/message.hpp, dns.hpp, serialize.hpp

/// DNS query type constants.
pub const QTYPE_A: u16 = 1;
pub const QTYPE_NS: u16 = 2;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_PTR: u16 = 12;
pub const QTYPE_MX: u16 = 15;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_SRV: u16 = 33;

/// DNS class: Internet.
pub const QCLASS_IN: u16 = 1;

/// DNS header flags.
pub const FLAGS_QR: u16 = 1 << 15;     // Query (0) / Response (1)
pub const FLAGS_AA: u16 = 1 << 10;     // Authoritative Answer
pub const FLAGS_TC: u16 = 1 << 9;      // Truncated
pub const FLAGS_RD: u16 = 1 << 8;      // Recursion Desired
pub const FLAGS_RA: u16 = 1 << 7;      // Recursion Available

/// DNS response codes.
pub const RCODE_NOERROR: u16 = 0;
pub const RCODE_SERVFAIL: u16 = 2;
pub const RCODE_NAMEERROR: u16 = 3;

/// A single DNS question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A single DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRR {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

/// A complete DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRR>,
    pub authorities: Vec<DnsRR>,
    pub additional: Vec<DnsRR>,
}

impl DnsMessage {
    /// Create a new empty DNS message.
    pub fn new(id: u16) -> Self {
        Self { id, flags: 0, questions: vec![], answers: vec![], authorities: vec![], additional: vec![] }
    }

    /// Create a DNS response from a query message.
    pub fn response_from(query: &DnsMessage) -> Self {
        let mut resp = Self::new(query.id);
        resp.flags = FLAGS_QR | FLAGS_AA;
        resp.questions = query.questions.clone();
        resp
    }

    /// Set the response code.
    pub fn set_rcode(&mut self, rcode: u16) {
        self.flags = (self.flags & !0xF) | (rcode & 0xF);
    }

    /// Add an A (IPv4 address) answer.
    pub fn add_a_answer(&mut self, name: &str, ip: [u8; 4], ttl: u32) {
        self.answers.push(DnsRR { name: name.to_string(), rtype: QTYPE_A, rclass: QCLASS_IN, ttl, rdata: ip.to_vec() });
    }

    /// Add a ServFail response.
    pub fn add_serv_fail(&mut self) {
        self.set_rcode(RCODE_SERVFAIL);
        self.answers.clear();
    }

    /// Add an NXDOMAIN response.
    pub fn add_nx_reply(&mut self) {
        self.set_rcode(RCODE_NAMEERROR);
        self.answers.clear();
    }

    /// Parse a DNS message from wire format bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 12 { return None; }
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
        let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
        let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

        let mut pos = 12;
        let mut questions = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            let (name, new_pos) = decode_name(data, pos)?;
            if new_pos + 4 > data.len() { return None; }
            let qtype = u16::from_be_bytes([data[new_pos], data[new_pos+1]]);
            let qclass = u16::from_be_bytes([data[new_pos+2], data[new_pos+3]]);
            questions.push(DnsQuestion { name, qtype, qclass });
            pos = new_pos + 4;
        }

        let mut answers = Vec::with_capacity(ancount);
        for _ in 0..ancount {
            match decode_rr(data, &mut pos) {
                Some(rr) => answers.push(rr),
                None => return None,
            }
        }
        let mut authorities = Vec::with_capacity(nscount);
        for _ in 0..nscount {
            match decode_rr(data, &mut pos) {
                Some(rr) => authorities.push(rr),
                None => return None,
            }
        }
        let mut additional = Vec::with_capacity(arcount);
        for _ in 0..arcount {
            match decode_rr(data, &mut pos) {
                Some(rr) => additional.push(rr),
                None => return None,
            }
        }

        Some(Self { id, flags, questions, answers, authorities, additional })
    }

    /// Encode this message to wire format bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.additional.len() as u16).to_be_bytes());

        for q in &self.questions {
            encode_name(&mut buf, &q.name);
            buf.extend_from_slice(&q.qtype.to_be_bytes());
            buf.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for rr in &self.answers { encode_rr(&mut buf, rr); }
        for rr in &self.authorities { encode_rr(&mut buf, rr); }
        for rr in &self.additional { encode_rr(&mut buf, rr); }
        buf
    }
}

/// Encode a DNS name in label format.
fn encode_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() { continue; }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // terminating zero-length label
}

/// Decode a DNS name from label format at position pos.
/// Returns (name, new_position) or None on error.
fn decode_name(data: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut p = pos;
    loop {
        if p >= data.len() { return None; }
        let len = data[p] as usize;
        if len == 0 { p += 1; break; }
        // Check for compression pointer (top 2 bits set)
        if len & 0xC0 == 0xC0 {
            if p + 1 >= data.len() { return None; }
            let ptr = (((len & 0x3F) as usize) << 8) | (data[p+1] as usize);
            let (suffix, _) = decode_name(data, ptr)?;
            if !name.is_empty() { name.push('.'); }
            name.push_str(&suffix);
            p += 2; break;
        }
        if p + 1 + len > data.len() { return None; }
        if !name.is_empty() { name.push('.'); }
        name.push_str(std::str::from_utf8(&data[p+1..p+1+len]).ok()?);
        p += 1 + len;
    }
    Some((name, p))
}

/// Decode a resource record.
fn decode_rr(data: &[u8], pos: &mut usize) -> Option<DnsRR> {
    let (name, p) = decode_name(data, *pos)?;
    if p + 10 > data.len() { return None; }
    let rtype = u16::from_be_bytes([data[p], data[p+1]]);
    let rclass = u16::from_be_bytes([data[p+2], data[p+3]]);
    let ttl = u32::from_be_bytes([data[p+4], data[p+5], data[p+6], data[p+7]]);
    let rdlen = u16::from_be_bytes([data[p+8], data[p+9]]) as usize;
    let data_start = p + 10;
    if data_start + rdlen > data.len() { return None; }
    let rdata = data[data_start..data_start+rdlen].to_vec();
    *pos = data_start + rdlen;
    Some(DnsRR { name, rtype, rclass, ttl, rdata })
}

/// Encode a resource record.
fn encode_rr(buf: &mut Vec<u8>, rr: &DnsRR) {
    encode_name(buf, &rr.name);
    buf.extend_from_slice(&rr.rtype.to_be_bytes());
    buf.extend_from_slice(&rr.rclass.to_be_bytes());
    buf.extend_from_slice(&rr.ttl.to_be_bytes());
    buf.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(&rr.rdata);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_name_simple() {
        let mut buf = Vec::new();
        encode_name(&mut buf, "example.com");
        let (name, pos) = decode_name(&buf, 0).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn test_decode_minimal_query() {
        // A DNS query for "example.com" type A
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x12, 0x34]); // ID
        buf.extend_from_slice(&[0x01, 0x00]); // flags: RD
        buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
        encode_name(&mut buf, "example.com");
        buf.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        buf.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

        let msg = DnsMessage::decode(&buf).unwrap();
        assert_eq!(msg.id, 0x1234);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com");
        assert_eq!(msg.questions[0].qtype, QTYPE_A);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut msg = DnsMessage::new(42);
        msg.flags = FLAGS_QR;
        msg.questions.push(DnsQuestion { name: "test.loki".into(), qtype: QTYPE_A, qclass: QCLASS_IN });
        msg.add_a_answer("test.loki", [10, 0, 0, 1], 60);

        let encoded = msg.encode();
        let decoded = DnsMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.id, 42);
        assert_eq!(decoded.questions.len(), 1);
        assert_eq!(decoded.questions[0].name, "test.loki");
        assert_eq!(decoded.answers.len(), 1);
        assert_eq!(decoded.answers[0].name, "test.loki");
        assert_eq!(decoded.answers[0].rdata, vec![10, 0, 0, 1]);
    }

    #[test]
    fn test_response_from_query() {
        let mut query = DnsMessage::new(99);
        query.questions.push(DnsQuestion { name: "foo.loki".into(), qtype: QTYPE_A, qclass: QCLASS_IN });
        let resp = DnsMessage::response_from(&query);
        assert_eq!(resp.id, 99);
        assert_eq!(resp.flags & FLAGS_QR, FLAGS_QR);
        assert_eq!(resp.questions.len(), 1);
    }

    #[test]
    fn test_serv_fail() {
        let mut msg = DnsMessage::new(1);
        msg.questions.push(DnsQuestion { name: "x.loki".into(), qtype: QTYPE_A, qclass: QCLASS_IN });
        msg.add_a_answer("x.loki", [1, 2, 3, 4], 10);
        msg.add_serv_fail();
        assert_eq!(msg.flags & 0xF, RCODE_SERVFAIL);
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn test_decode_empty_packet() {
        assert!(DnsMessage::decode(&[]).is_none());
        assert!(DnsMessage::decode(&[0u8; 5]).is_none());
    }

    #[test]
    fn test_encode_name_multi_label() {
        let mut buf = Vec::new();
        encode_name(&mut buf, "a.b.c.example.com");
        let (name, _) = decode_name(&buf, 0).unwrap();
        assert_eq!(name, "a.b.c.example.com");
    }
}
