use std::io;

/// Simple buffer writer for building byte sequences.
pub struct BufferWriter {
    buf: Vec<u8>,
}

impl BufferWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn put_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn put_u16_be(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_u32_be(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_u64_be(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Default for BufferWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple buffer reader for consuming byte sequences.
pub struct BufferReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BufferReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn read_u8(&mut self) -> io::Result<u8> {
        if self.pos >= self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffer underflow reading u8",
            ));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16_be(&mut self) -> io::Result<u16> {
        if self.pos + 2 > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffer underflow reading u16",
            ));
        }
        let bytes: [u8; 2] = self.data[self.pos..self.pos + 2].try_into().unwrap();
        self.pos += 2;
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn read_u32_be(&mut self) -> io::Result<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffer underflow reading u32",
            ));
        }
        let bytes: [u8; 4] = self.data[self.pos..self.pos + 4].try_into().unwrap();
        self.pos += 4;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn read_u64_be(&mut self) -> io::Result<u64> {
        if self.pos + 8 > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffer underflow reading u64",
            ));
        }
        let bytes: [u8; 8] = self.data[self.pos..self.pos + 8].try_into().unwrap();
        self.pos += 8;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn read_bytes(&mut self, len: usize) -> io::Result<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffer underflow reading bytes",
            ));
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn position(&self) -> usize {
        self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_read_roundtrip() {
        let mut w = BufferWriter::new();
        w.put_u8(0x01);
        w.put_u16_be(0x0203);
        w.put_u32_be(0x04050607);
        w.put_u64_be(0x08090A0B0C0D0E0F);
        w.put_bytes(&[0x10, 0x11, 0x12]);

        let data = w.into_vec();

        let mut r = BufferReader::new(&data);
        assert_eq!(r.read_u8().unwrap(), 0x01);
        assert_eq!(r.read_u16_be().unwrap(), 0x0203);
        assert_eq!(r.read_u32_be().unwrap(), 0x04050607);
        assert_eq!(r.read_u64_be().unwrap(), 0x08090A0B0C0D0E0F);
        assert_eq!(r.read_bytes(3).unwrap(), &[0x10, 0x11, 0x12]);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn test_buffer_overflow() {
        let data = vec![0x01, 0x02];
        let mut r = BufferReader::new(&data);
        assert!(r.read_u16_be().is_ok());
        assert!(r.read_u8().is_err());
    }

    #[test]
    fn test_len_and_default() {
        let mut w = BufferWriter::default();
        assert_eq!(w.len(), 0);
        assert!(w.is_empty());
        w.put_u8(42);
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn test_with_capacity() {
        let w = BufferWriter::with_capacity(100);
        assert_eq!(w.len(), 0);
    }
}
