use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use parking_lot::RwLock;
use bytes::Bytes;
use crate::traits::*;

/// Manages QUIC connections to remote SaferunNet routers.
/// Lokinet C++ equivalent: llarp/link/link_manager.hpp LinkManager
pub struct LinkManager {
    transport: Arc<dyn TransportLayer>,
    connections: RwLock<HashMap<SocketAddr, Box<dyn Connection>>>,
}

impl LinkManager {
    pub fn new(transport: Arc<dyn TransportLayer>) -> Self {
        Self {
            transport,
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Connect to a remote peer
    pub async fn connect(&self, addr: SocketAddr) -> TransportResult<()> {
        if self.connections.read().contains_key(&addr) {
            return Ok(());
        }
        let conn = self.transport.connect(addr).await?;
        self.connections.write().insert(addr, conn);
        Ok(())
    }

    /// Send an unreliable datagram message
    pub async fn send_data_message(
        &self,
        addr: &SocketAddr,
        data: Bytes,
    ) -> TransportResult<()> {
        let guard = self.connections.read();
        let conn = guard
            .get(addr)
            .ok_or_else(|| TransportError::NotFound(format!("no connection to {}", addr)))?;
        conn.send_datagram(data).await
    }

    /// Send a control message and await response
    pub async fn send_control_message(
        &self,
        addr: &SocketAddr,
        data: Bytes,
    ) -> TransportResult<Bytes> {
        let guard = self.connections.read();
        let conn = guard
            .get(addr)
            .ok_or_else(|| TransportError::NotFound(format!("no connection to {}", addr)))?;
        let mut stream = conn.open_stream().await?;
        stream.send(data).await?;
        stream.finish().await?;
        stream
            .recv()
            .await?
            .ok_or_else(|| TransportError::NotFound("empty response".into()))
    }

    /// Close connection to a peer
    pub fn close_connection(&self, addr: &SocketAddr) {
        if let Some(conn) = self.connections.write().remove(addr) {
            tokio::spawn(async move {
                conn.close(0).await;
            });
        }
    }

    /// Check if we have an active connection
    pub fn have_connection_to(&self, addr: &SocketAddr) -> bool {
        self.connections.read().contains_key(addr)
    }

    /// Iterate over all connections
    pub fn for_each_connection<F>(&self, f: F)
    where
        F: Fn(&SocketAddr, &dyn Connection),
    {
        for (addr, conn) in self.connections.read().iter() {
            f(addr, conn.as_ref());
        }
    }
}
