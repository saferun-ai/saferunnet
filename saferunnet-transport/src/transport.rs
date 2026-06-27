use std::net::SocketAddr;
pub use crate::traits::TransportError;

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
