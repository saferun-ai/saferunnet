pub mod buffer;
pub mod file;
pub mod random;
pub mod time;

// ── String Utilities ─────────────────────────────────────────────────────

pub fn split_any(s: &str, delimiters: &[char]) -> Vec<String> {
    s.split(delimiters).map(|p| p.to_string()).collect()
}

pub fn join_strings(v: &[String], sep: &str) -> String { v.join(sep) }

pub fn parse_int(s: &str) -> Result<i64, std::num::ParseIntError> {
    s.trim().parse::<i64>()
}

pub fn trim_whitespace(s: &str) -> String { s.trim().to_string() }

pub fn lowercase_ascii_string(s: &str) -> String { s.to_ascii_lowercase() }

// ── Memory Debug Utilities ────────────────────────────────────────────────

pub fn dump_buffer(data: &[u8]) -> String {
    let mut output = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        output.push_str(&format!("{:08x}  ", offset));
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x} ", byte));
            if j == 7 { output.push(' '); }
        }
        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                output.push_str("   ");
                if j == 7 { output.push(' '); }
            }
        }
        output.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' { output.push(*byte as char); }
            else { output.push('.'); }
        }
        output.push_str("|\n");
    }
    output
}

pub fn dump_buffer_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_any() {
        assert_eq!(split_any("a,b,c", &[',']), vec!["a", "b", "c"]);
        assert_eq!(split_any("a,b;c", &[',', ';']), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_join_strings() {
        assert_eq!(join_strings(&["a".into(), "b".into()], "|"), "a|b");
    }

    #[test]
    fn test_parse_int() {
        assert_eq!(parse_int("42").unwrap(), 42);
        assert!(parse_int("abc").is_err());
    }

    #[test]
    fn test_trim_whitespace() {
        assert_eq!(trim_whitespace("  hi  "), "hi");
    }

    #[test]
    fn test_lowercase_ascii_string() {
        assert_eq!(lowercase_ascii_string("HELLO"), "hello");
    }

    #[test]
    fn test_dump_buffer_hex() {
        assert_eq!(dump_buffer_hex(b"abc"), "616263");
        assert_eq!(dump_buffer_hex(&[]), "");
    }

    #[test]
    fn test_dump_buffer() {
        let result = dump_buffer(b"Hi");
        assert!(result.contains("00000000"));
        assert!(result.contains("|Hi"));
    }
}