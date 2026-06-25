const SESSION_HOP_ID_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionHopId([u8; SESSION_HOP_ID_LEN]);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTag(u32);

impl SessionTag {
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for SessionTag {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}
