//! In-memory simulated network for integration tests.
//!
//! Provides `SimTransport` (in-memory transport implementing `LinkTransport`)
//! and `SimNetwork` (a shared hub that routes messages between transports).

use crate::transport::{Datagram, LinkTransport, TransportError};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

/// A shared simulated network hub that routes datagrams between transports.
pub struct SimNetwork {
    queues: Mutex<HashMap<SocketAddr, Vec<Datagram>>>,
}

impl SimNetwork {
    pub fn new() -> Self {
        Self {
            queues: Mutex::new(HashMap::new()),
        }
    }

    fn deliver(&self, datagram: Datagram) {
        let mut queues = self.queues.lock().unwrap();
        queues
            .entry(datagram.remote)
            .or_insert_with(Vec::new)
            .push(datagram);
    }

    fn recv(&self, addr: SocketAddr) -> Option<Datagram> {
        let mut queues = self.queues.lock().unwrap();
        queues
            .get_mut(&addr)
            .and_then(|q| if q.is_empty() { None } else { Some(q.remove(0)) })
    }
}

/// An in-memory transport that routes through a shared `SimNetwork`.
pub struct SimTransport {
    addr: SocketAddr,
    network: std::sync::Arc<Mutex<SimNetwork>>,
}

impl SimTransport {
    pub fn new(addr: SocketAddr, network: std::sync::Arc<Mutex<SimNetwork>>) -> Self {
        Self { addr, network }
    }
}

impl LinkTransport for SimTransport {
    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize, TransportError> {
        let len = data.len();
        let datagram = Datagram {
            data: data.to_vec(),
            remote: addr,
        };
        self.network.lock().unwrap().deliver(datagram);
        Ok(len)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<Datagram, TransportError> {
        loop {
            if let Some(datagram) = self.network.lock().unwrap().recv(self.addr) {
                let len = datagram.data.len().min(buf.len());
                buf[..len].copy_from_slice(&datagram.data[..len]);
                return Ok(Datagram {
                    data: datagram.data[..len].to_vec(),
                    remote: datagram.remote,
                });
            }
            // Yield to the runtime instead of busy-waiting
            tokio::task::yield_now().await;
        }
    }

    fn close(&self) {}
}
