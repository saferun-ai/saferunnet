use rand::RngCore;

/// Fill `buf` with cryptographically random bytes.
pub fn random_bytes(buf: &mut [u8]) {
    rand::thread_rng().fill_bytes(buf);
}

/// Return a random u64.
pub fn random_u64() -> u64 {
    rand::thread_rng().next_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes_vary() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        random_bytes(&mut a);
        random_bytes(&mut b);
        assert_ne!(a, b, "random_bytes should produce different values");
    }

    #[test]
    fn test_random_u64_vary() {
        let x = random_u64();
        let y = random_u64();
        assert_ne!(x, y, "random_u64 should produce different values");
    }
}
