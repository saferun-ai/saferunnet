use serde::{Deserialize, Serialize};

/// DNS SRV record data for service discovery.
/// Lokinet C++ equivalent: llarp/dns/srv_data.hpp SRVData
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SrvData {
    pub proto: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

impl SrvData {
    pub fn new(proto: String, priority: u16, weight: u16, port: u16, target: String) -> Self {
        Self { proto, priority, weight, port, target }
    }

    /// Serialize to wire-format bytes (simplified — lokinet uses bt-encoding, we use a simple packed format).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.target.len() + 8);
        buf.extend_from_slice(&self.priority.to_be_bytes());
        buf.extend_from_slice(&self.weight.to_be_bytes());
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf.extend_from_slice(self.target.as_bytes());
        buf.push(0); // null terminator
        buf
    }

    /// Deserialize from wire-format bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 7 { return None; }
        let priority = u16::from_be_bytes([data[0], data[1]]);
        let weight = u16::from_be_bytes([data[2], data[3]]);
        let port = u16::from_be_bytes([data[4], data[5]]);
        let rest = &data[6..];
        let nul = rest.iter().position(|&b| b == 0)?;
        let target = String::from_utf8_lossy(&rest[..nul]).to_string();
        Some(Self { proto: "tcp".into(), priority, weight, port, target })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn test_srv_encode_decode() { let s = SrvData::new("tcp".into(), 10, 5, 1090, "node.loki".into()); let encoded = s.encode(); let decoded = SrvData::decode(&encoded).unwrap(); assert_eq!(decoded.priority, 10); assert_eq!(decoded.port, 1090); assert_eq!(decoded.target, "node.loki"); }
    #[test] fn test_srv_serde() { let s = SrvData::new("tcp".into(), 1, 2, 3, "test.sfr".into()); let json = serde_json::to_string(&s).unwrap(); let d: SrvData = serde_json::from_str(&json).unwrap(); assert_eq!(d, s); }
}
