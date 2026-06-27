use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use saferunnet_transport::{Datagram, LinkTransport, TransportError};
use tokio::sync::mpsc;

use crate::sim_network::SimNetwork;

type PacketReceiver = Mutex<Option<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>>;

/// A simulated transport that routes through an in-memory `SimNetwork`.
///
/// Implements `LinkTransport` for integration testing without real sockets.
pub struct SimTransport {
    local_addr: SocketAddr,
    network: Arc<Mutex<SimNetwork>>,
    rx: PacketReceiver,
    closed: Mutex<bool>,
}

impl SimTransport {
    /// Create a new simulated transport registered at the given address on the network.
    pub fn new(addr: SocketAddr, network: Arc<Mutex<SimNetwork>>) -> Self {
        let rx = {
            let mut net = network.lock().unwrap();
            net.register(addr)
        };
        Self {
            local_addr: addr,
            network,
            rx: Mutex::new(Some(rx)),
            closed: Mutex::new(false),
        }
    }
}

impl LinkTransport for SimTransport {
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize, TransportError> {
        if *self.closed.lock().unwrap() {
            return Err(TransportError::Closed);
        }
        let net = self.network.lock().unwrap();
        let len = data.len();
        if net.send_to(data, self.local_addr, addr) {
            Ok(len)
        } else {
            Err(TransportError::SendFailed(format!("no route to {addr}")))
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<Datagram, TransportError> {
        let mut rx = {
            let mut guard = self.rx.lock().unwrap();
            guard.take().ok_or(TransportError::Closed)?
        };

        let result = match rx.recv().await {
            Some((data, remote)) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(Datagram {
                    data: data.to_vec(),
                    remote,
                })
            }
            None => Err(TransportError::Closed),
        };

        // Put the receiver back for subsequent calls
        *self.rx.lock().unwrap() = Some(rx);
        result
    }

    fn close(&self) {
        *self.closed.lock().unwrap() = true;
    }
}
