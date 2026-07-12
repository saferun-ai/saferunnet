const SESSION_HOP_ID_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionHopId(pub [u8; SESSION_HOP_ID_LEN]);

impl SessionHopId {
    pub fn new(bytes: [u8; SESSION_HOP_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SESSION_HOP_ID_LEN] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; SESSION_HOP_ID_LEN] {
        self.0
    }
}

impl From<[u8; SESSION_HOP_ID_LEN]> for SessionHopId {
    fn from(bytes: [u8; SESSION_HOP_ID_LEN]) -> Self {
        Self::new(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionTag(pub u32);

impl SessionTag {
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    pub fn get(self) -> u32 {
        self.0
    }

    /// Convert to a 4-byte representation for serialisation.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }

    /// Reconstruct from a 4-byte representation.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut buf = [0u8; 4];
        let len = bytes.len().min(4);
        buf[..len].copy_from_slice(&bytes[..len]);
        Self(u32::from_be_bytes(buf))
    }
}


/// XOR factor used to differentiate path-switch nonces from session-init nonces.
/// Lokinet C++ equivalent: `llarp/session.hpp` `switch_xor_factor`.
///
/// When generating an encryption nonce for a path-switch message, XOR this
/// constant with the session tag to prevent collision with session-init nonces
/// that are derived from different input material.
pub const SWITCH_XOR_FACTOR: u32 = 0xC305_1F20;

/// Apply the switch XOR factor to a session tag to produce a distinct nonce base.
pub fn apply_switch_xor(tag: SessionTag) -> u32 {
    tag.get() ^ SWITCH_XOR_FACTOR
}
impl From<u32> for SessionTag {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}
