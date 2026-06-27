use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;

/// Result type for transport operations
pub type TransportResult<T> = Result<T, TransportError>;

/// Transport layer errors
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

/// Type alias for the transport used by LinkManager
pub type LinkManagerTransport = Arc<dyn TransportLayer>;

/// Abstract transport layer, enabling mock implementations for testing.
/// Lokinet C++ equivalent: quic::Connection + quic::Datagrams + quic::BTRequestStream
#[async_trait]
pub trait TransportLayer: Send + Sync {
    /// Connect to a remote peer. Returns a connection handle.
    async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn Connection>>;

    /// Listen for incoming connections.
    async fn listen(&self, addr: SocketAddr) -> TransportResult<Box<dyn Listener>>;
}

/// An established QUIC connection to a remote peer.
/// Lokinet C++ equivalent: quic::Connection
#[async_trait]
pub trait Connection: Send + Sync {
    /// Send an unreliable datagram (RFC 9221)
    async fn send_datagram(&self, data: Bytes) -> TransportResult<()>;

    /// Receive an unreliable datagram (RFC 9221)
    async fn recv_datagram(&self) -> TransportResult<Bytes>;

    /// Open a bidirectional control stream
    /// Lokinet C++ equivalent: BTRequestStream
    async fn open_stream(&self) -> TransportResult<Box<dyn ControlStream>>;

    /// Accept an incoming bidirectional stream
    async fn accept_stream(&self) -> TransportResult<Box<dyn ControlStream>>;

    /// Close the connection
    async fn close(&self, error_code: u64);

    /// Peer address
    fn remote_addr(&self) -> SocketAddr;

    /// Whether this is an inbound connection
    fn is_inbound(&self) -> bool;

    /// Clone the connection handle (for shared access)
    fn clone_connection(&self) -> Box<dyn Connection>;
}

/// A bidirectional control stream for request/response patterns.
/// Lokinet C++ equivalent: quic::BTRequestStream
#[async_trait]
pub trait ControlStream: Send + Sync {
    /// Send bytes on the stream
    async fn send(&mut self, data: Bytes) -> TransportResult<()>;

    /// Receive bytes from the stream
    async fn recv(&mut self) -> TransportResult<Option<Bytes>>;

    /// Close the stream
    async fn finish(&mut self) -> TransportResult<()>;
}

/// Accepts incoming connections.
#[async_trait]
pub trait Listener: Send + Sync {
    /// Accept the next incoming connection
    async fn accept(&self) -> TransportResult<(Box<dyn Connection>, SocketAddr)>;

    /// Local address being listened on
    fn local_addr(&self) -> SocketAddr;
}
