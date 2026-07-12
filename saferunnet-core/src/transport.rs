use std::net::SocketAddr;

/// Transport-level error type shared across the project.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("bind failed: {0}")]
    BindFailed(String),
    #[error("recv failed: {0}")]
    RecvFailed(String),
    #[error("connection closed")]
    Closed,
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("not found: {0}")]
    NotFound(String),
}

/// A single datagram received from the network.
#[derive(Debug, Clone)]
pub struct Datagram {
    pub data: Vec<u8>,
    pub remote: SocketAddr,
}

/// Trait for link-layer transport — async send/recv of datagrams.
/// Used by the DHT and other low-level networking code.
#[allow(async_fn_in_trait)]
pub trait LinkTransport: Send + Sync {
    fn local_addr(&self) -> SocketAddr;
    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize, TransportError>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<Datagram, TransportError>;
    fn close(&self);
}
