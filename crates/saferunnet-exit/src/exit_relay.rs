use thiserror::Error;

/// Minimum payload size for an exit target: 1 (addr_len) + 0 (min addr) + 2 (port) = 3
const MIN_EXIT_TARGET_LEN: usize = 3;

/// Parse the exit target from a decrypted relay payload.
///
/// Format: 1-byte address length (u8), N-byte address (ASCII), 2-byte port (big-endian u16).
pub fn parse_exit_target(payload: &[u8]) -> Result<(String, u16), ExitParseError> {
    if payload.len() < MIN_EXIT_TARGET_LEN {
        return Err(ExitParseError::Truncated {
            expected: MIN_EXIT_TARGET_LEN,
            found: payload.len(),
        });
    }

    let addr_len = payload[0] as usize;
    let addr_end = 1 + addr_len;
    let port_start = addr_end;

    if payload.len() < port_start + 2 {
        return Err(ExitParseError::Truncated {
            expected: port_start + 2,
            found: payload.len(),
        });
    }

    let addr_bytes = &payload[1..addr_end];
    let addr =
        String::from_utf8(addr_bytes.to_vec()).map_err(|_| ExitParseError::InvalidAddress)?;

    if addr.is_empty() {
        return Err(ExitParseError::InvalidAddress);
    }

    let port = u16::from_be_bytes([payload[port_start], payload[port_start + 1]]);

    Ok((addr, port))
}

/// Encode an exit target into payload bytes.
pub fn encode_exit_target(
    addr: &str,
    port: u16,
    payload: &mut Vec<u8>,
) -> Result<(), ExitParseError> {
    let addr_bytes = addr.as_bytes();
    if addr_bytes.len() > 255 {
        return Err(ExitParseError::InvalidAddress);
    }
    payload.push(addr_bytes.len() as u8);
    payload.extend_from_slice(addr_bytes);
    payload.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExitParseError {
    #[error("exit target payload truncated: need {expected} bytes, found {found}")]
    Truncated { expected: usize, found: usize },
    #[error("invalid exit target address")]
    InvalidAddress,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_exit_target() {
        // Build: addr_len=9, addr="example.com", port=443
        let mut payload = Vec::new();
        payload.push(11);
        payload.extend_from_slice(b"example.com");
        payload.extend_from_slice(&443u16.to_be_bytes());

        let (addr, port) = parse_exit_target(&payload).unwrap();
        assert_eq!(addr, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_exit_target_http() {
        let mut payload = Vec::new();
        encode_exit_target("api.example.org", 80, &mut payload).unwrap();

        let (addr, port) = parse_exit_target(&payload).unwrap();
        assert_eq!(addr, "api.example.org");
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_exit_target_roundtrip() {
        let cases = [
            ("localhost", 8080u16),
            ("10.0.0.1", 1090),
            ("exit.node.internal", 443),
            ("a", 1),
        ];
        for (addr, port) in cases {
            let mut payload = Vec::new();
            encode_exit_target(addr, port, &mut payload).unwrap();
            let (decoded_addr, decoded_port) = parse_exit_target(&payload).unwrap();
            assert_eq!(decoded_addr, addr);
            assert_eq!(decoded_port, port);
        }
    }

    #[test]
    fn reject_truncated_header() {
        let result = parse_exit_target(&[5]);
        assert!(matches!(result, Err(ExitParseError::Truncated { .. })));
    }

    #[test]
    fn reject_truncated_address() {
        // addr_len=10 but only 3 bytes follow
        let mut payload = vec![10];
        payload.extend_from_slice(b"abc");
        let result = parse_exit_target(&payload);
        assert!(matches!(result, Err(ExitParseError::Truncated { .. })));
    }

    #[test]
    fn reject_truncated_port() {
        // addr_len=3, addr="abc", port needs 2 bytes but only 1
        let mut payload = vec![3];
        payload.extend_from_slice(b"abc");
        payload.push(0x01);
        let result = parse_exit_target(&payload);
        assert!(matches!(result, Err(ExitParseError::Truncated { .. })));
    }

    #[test]
    fn reject_empty_address() {
        let payload = vec![0, 0x01, 0xBB];
        let result = parse_exit_target(&payload);
        assert!(matches!(result, Err(ExitParseError::InvalidAddress)));
    }

    #[test]
    fn encode_rejects_oversize_address() {
        let big_addr = "a".repeat(256);
        let mut payload = Vec::new();
        let result = encode_exit_target(&big_addr, 80, &mut payload);
        assert!(result.is_err());
    }
}
