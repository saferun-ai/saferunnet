use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("failed to create TUN device: {0}")]
    CreateFailed(String),
    #[error("failed to read from TUN device: {0}")]
    ReadFailed(String),
    #[error("failed to write to TUN device: {0}")]
    WriteFailed(String),
}

pub trait TunDevice {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError>;
    fn write(&mut self, buf: &[u8]) -> Result<usize, TunError>;
    fn mtu(&self) -> usize;
}

#[derive(Debug, Default)]
pub struct StubTunDevice;

impl TunDevice for StubTunDevice {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, TunError> {
        Ok(0)
    }
    fn write(&mut self, _buf: &[u8]) -> Result<usize, TunError> {
        Ok(0)
    }
    fn mtu(&self) -> usize {
        1500
    }
}
