use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("bind failed: {0}")]
    BindFailed(String),
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("recv failed: {0}")]
    RecvFailed(String),
    #[error("connection closed")]
    Closed,
}

/// A single datagram received from the network.
#[derive(Debug, Clone)]
pub struct Datagram {
    pub data: Vec<u8>,
    pub remote: SocketAddr,
}

/// Trait for link-layer transport — async send/recv of datagrams.
#[allow(async_fn_in_trait)]
pub trait LinkTransport: Send + Sync {
    fn local_addr(&self) -> SocketAddr;
    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize, TransportError>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<Datagram, TransportError>;
    fn close(&self);
}
