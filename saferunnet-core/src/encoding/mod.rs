/// Minimal bencode implementation for Oxen protocol compatibility.
/// Lokinet C++ equivalent: oxen-encoding (bt_dict, bt_list, bt_value)

#[derive(Debug, Clone, PartialEq)]
pub enum BtValue {
    String(Vec<u8>),
    Integer(i64),
    List(Vec<BtValue>),
    Dict(Vec<(String, BtValue)>),
}

impl BtValue {
    /// Encode to bencode bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            BtValue::String(s) => {
                out.extend_from_slice(s.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(s);
            }
            BtValue::Integer(i) => {
                out.extend_from_slice(format!("i{}e", i).as_bytes());
            }
            BtValue::List(list) => {
                out.push(b'l');
                for item in list {
                    item.encode_into(out);
                }
                out.push(b'e');
            }
            BtValue::Dict(dict) => {
                out.push(b'd');
                for (key, value) in dict {
                    // Keys must be strings
                    let key_bytes = key.as_bytes();
                    out.extend_from_slice(key_bytes.len().to_string().as_bytes());
                    out.push(b':');
                    out.extend_from_slice(key_bytes);
                    value.encode_into(out);
                }
                out.push(b'e');
            }
        }
    }

    /// Decode from bencode bytes
    pub fn decode(data: &[u8]) -> Result<(Self, usize), String> {
        if data.is_empty() {
            return Err("empty input".into());
        }
        match data[0] {
            b'i' => Self::decode_int(data),
            b'l' => Self::decode_list(data),
            b'd' => Self::decode_dict(data),
            b'0'..=b'9' => Self::decode_string(data),
            _ => Err(format!("unexpected byte: {}", data[0])),
        }
    }

    fn decode_int(data: &[u8]) -> Result<(Self, usize), String> {
        let end = data
            .iter()
            .position(|&b| b == b'e')
            .ok_or("missing 'e' in integer")?;
        let s = std::str::from_utf8(&data[1..end]).map_err(|_| "invalid utf8 in int")?;
        let val = s.parse::<i64>().map_err(|_| "invalid integer")?;
        Ok((BtValue::Integer(val), end + 1))
    }

    fn decode_string(data: &[u8]) -> Result<(Self, usize), String> {
        let colon = data
            .iter()
            .position(|&b| b == b':')
            .ok_or("missing ':' in string")?;
        let len_str =
            std::str::from_utf8(&data[..colon]).map_err(|_| "invalid utf8 in string len")?;
        let len = len_str
            .parse::<usize>()
            .map_err(|_| "invalid string length")?;
        let end = colon + 1 + len;
        if end > data.len() {
            return Err("string truncated".into());
        }
        Ok((BtValue::String(data[colon + 1..end].to_vec()), end))
    }

    fn decode_list(data: &[u8]) -> Result<(Self, usize), String> {
        let mut items = Vec::new();
        let mut pos = 1;
        while pos < data.len() && data[pos] != b'e' {
            let (item, consumed) = BtValue::decode(&data[pos..])?;
            items.push(item);
            pos += consumed;
        }
        if pos >= data.len() {
            return Err("missing 'e' in list".into());
        }
        Ok((BtValue::List(items), pos + 1))
    }

    fn decode_dict(data: &[u8]) -> Result<(Self, usize), String> {
        let mut items = Vec::new();
        let mut pos = 1;
        while pos < data.len() && data[pos] != b'e' {
            let (key_val, key_consumed) = BtValue::decode_string(&data[pos..])?;
            pos += key_consumed;
            let key = match key_val {
                BtValue::String(s) => String::from_utf8(s).map_err(|_| "invalid utf8 key")?,
                _ => return Err("dict key must be string".into()),
            };
            let (value, val_consumed) = BtValue::decode(&data[pos..])?;
            pos += val_consumed;
            items.push((key, value));
        }
        if pos >= data.len() {
            return Err("missing 'e' in dict".into());
        }
        Ok((BtValue::Dict(items), pos + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_int() {
        let val = BtValue::Integer(42);
        let encoded = val.encode();
        assert_eq!(encoded, b"i42e");
        let (decoded, _) = BtValue::decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_encode_decode_string() {
        let val = BtValue::String(b"hello".to_vec());
        let encoded = val.encode();
        assert_eq!(encoded, b"5:hello");
        let (decoded, _) = BtValue::decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_encode_decode_list() {
        let val = BtValue::List(vec![BtValue::Integer(1), BtValue::String(b"ab".to_vec())]);
        let encoded = val.encode();
        assert_eq!(encoded, b"li1e2:abe");
        let (decoded, _) = BtValue::decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_encode_decode_dict() {
        let val = BtValue::Dict(vec![("key".into(), BtValue::Integer(100))]);
        let encoded = val.encode();
        let (decoded, _) = BtValue::decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }
}

// ── BtDict wrapper ─────────────────────────────────────────────────────────

/// Dictionary wrapper for bencode encoding/decoding.
#[derive(Debug, Clone)]
pub struct BtDict {
    entries: Vec<(String, BtValue)>,
}

impl BtDict {
    pub fn new() -> Self { Self { entries: Vec::new() } }

    pub fn insert_int(mut self, key: &str, val: i64) -> Self {
        self.entries.push((key.to_string(), BtValue::Integer(val)));
        self
    }

    pub fn insert(mut self, key: &str, val: &[u8]) -> Self {
        self.entries.push((key.to_string(), BtValue::String(val.to_vec())));
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        BtValue::Dict(self.entries.clone()).encode()
    }

    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), String> {
        let (val, consumed) = BtValue::decode(data)?;
        match val {
            BtValue::Dict(entries) => Ok((Self { entries }, consumed)),
            _ => Err("not a dict".into()),
        }
    }

    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.entries.iter().find_map(|(k, v)| {
            if k == key {
                match v { BtValue::Integer(n) => Some(*n), _ => None }
            } else { None }
        })
    }

    pub fn get_list(&self, key: &str) -> Option<Vec<Vec<u8>>> {
        self.entries.iter().find_map(|(k, v)| {
            if k == key {
                match v {
                    BtValue::List(items) => {
                        let strings: Vec<Vec<u8>> = items.iter().filter_map(|item| {
                            match item { BtValue::String(s) => Some(s.clone()), _ => None }
                        }).collect();
                        Some(strings)
                    }
                    _ => None,
                }
            } else { None }
        })
    }
}