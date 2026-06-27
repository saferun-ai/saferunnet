use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use bytes::Bytes;
use crate::traits::{Connection, TransportResult};

/// TCP-over-QUIC tunnel for liblokinet-style TCP proxying.
/// Lokinet C++ equivalent: llarp/ev/tcp.hpp QUICTunnel
///
/// Each new TCP connection on the local port opens a new QUIC stream
/// over an existing QUIC connection to the remote peer.
pub struct QuicTunnel {
    quic_conn: Arc<dyn Connection>,
    local_port: u16,
}

impl QuicTunnel {
    pub fn new(quic_conn: Arc<dyn Connection>, local_port: u16) -> Self {
        Self {
            quic_conn,
            local_port,
        }
    }

    /// Start listening on a local TCP port and tunnel all connections
    pub async fn listen_and_serve(self) -> TransportResult<()> {
        let listener = TcpListener::bind(("127.0.0.1", self.local_port))
            .await
            .map_err(|e| crate::traits::TransportError::ConnectionFailed(e.to_string()))?;

        loop {
            let (tcp_stream, _addr) = listener
                .accept()
                .await
                .map_err(|e| crate::traits::TransportError::ConnectionFailed(e.to_string()))?;

            let conn = self.quic_conn.clone_connection();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_tcp_connection(conn, tcp_stream).await {
                    tracing::warn!("TCP tunnel stream error: {}", e);
                }
            });
        }
    }

    async fn handle_tcp_connection(
        conn: Box<dyn Connection>,
        tcp: tokio::net::TcpStream,
    ) -> TransportResult<()> {
        let mut quic_stream = conn.open_stream().await?;
        let (mut tcp_read, _tcp_write) = tcp.into_split();

        // TCP -> QUIC (write side)
        let mut buf = vec![0u8; 8192];
        loop {
            let n = tcp_read
                .read(&mut buf)
                .await
                .map_err(|e| crate::traits::TransportError::ConnectionFailed(e.to_string()))?;
            if n == 0 {
                break;
            }
            quic_stream
                .send(Bytes::from(buf[..n].to_vec()))
                .await?;
        }
        quic_stream.finish().await?;

        // Note: QUIC -> TCP direction requires a matching QuicTunnel on the remote side
        // that opens a TCP connection to the target and forwards data.
        // This is the client side; the server side QuicTunnel::handle_incoming()
        // handles the reverse direction.

        Ok(())
    }
}
