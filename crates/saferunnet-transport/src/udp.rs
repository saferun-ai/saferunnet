use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::transport::{Datagram, LinkTransport, TransportError};

/// UDP transport implementation using tokio.
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
}

impl UdpTransport {
    pub async fn bind(addr: SocketAddr) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| TransportError::BindFailed(e.to_string()))?;
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
        }
    }
}

impl LinkTransport for UdpTransport {
    fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
    }

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize, TransportError> {
        self.socket
            .send_to(data, addr)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<Datagram, TransportError> {
        let (len, remote) = self
            .socket
            .recv_from(buf)
            .await
            .map_err(|e| TransportError::RecvFailed(e.to_string()))?;
        Ok(Datagram {
            data: buf[..len].to_vec(),
            remote,
        })
    }

    fn close(&self) {
        // UDP is connectionless — no explicit close needed
    }
}
