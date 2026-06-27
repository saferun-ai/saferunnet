use crate::traits::*;
use async_trait::async_trait;
use bytes::Bytes;
use quinn::{Connection as QuinnConn, Endpoint, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// QUIC-based transport layer using quinn.
/// Lokinet C++ equivalent: oxen-libquic
pub struct QuinnTransport {
    endpoint: Endpoint,
}

impl QuinnTransport {
    pub fn new_server(
        bind_addr: SocketAddr,
        server_config: quinn::ServerConfig,
    ) -> TransportResult<Self> {
        let endpoint = Endpoint::server(server_config, bind_addr)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        Ok(Self { endpoint })
    }

    pub fn new_client(bind_addr: SocketAddr) -> TransportResult<Self> {
        let mut endpoint = Endpoint::client(bind_addr)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr().unwrap()
    }
}

#[async_trait]
impl TransportLayer for QuinnTransport {
    async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn Connection>> {
        let connection = self
            .endpoint
            .connect(addr, "saferunnet")
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        Ok(Box::new(QuinnConnection::new(connection)))
    }

    async fn listen(&self, _addr: SocketAddr) -> TransportResult<Box<dyn Listener>> {
        Ok(Box::new(QuinnListener {
            endpoint: self.endpoint.clone(),
        }))
    }
}

// --- QuinnConnection wraps quinn::Connection ---

struct QuinnConnectionInner {
    conn: QuinnConn,
    datagram_rx: Mutex<tokio::sync::mpsc::Receiver<Bytes>>,
}

pub struct QuinnConnection {
    inner: Arc<QuinnConnectionInner>,
}

impl QuinnConnection {
    fn new(conn: QuinnConn) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let conn_clone = conn.clone();
        tokio::spawn(async move {
            loop {
                match conn_clone.read_datagram().await {
                    Ok(datagram) => {
                        if tx.send(Bytes::from(datagram)).await.is_err() {
                            break;
                        }
                    }
                    Err(quinn::ConnectionError::LocallyClosed)
                    | Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
                    Err(_) => continue,
                }
            }
        });
        Self {
            inner: Arc::new(QuinnConnectionInner {
                conn,
                datagram_rx: Mutex::new(rx),
            }),
        }
    }
}

#[async_trait]
impl Connection for QuinnConnection {
    async fn send_datagram(&self, data: Bytes) -> TransportResult<()> {
        self.inner
            .conn
            .send_datagram(data.into())
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(())
    }

    async fn recv_datagram(&self) -> TransportResult<Bytes> {
        self.inner
            .datagram_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| TransportError::NotFound("datagram channel closed".into()))
    }

    async fn open_stream(&self) -> TransportResult<Box<dyn ControlStream>> {
        let (send, recv) = self
            .inner
            .conn
            .open_bi()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        Ok(Box::new(QuinnControlStream { send, recv }))
    }

    async fn accept_stream(&self) -> TransportResult<Box<dyn ControlStream>> {
        let (send, recv) = self
            .inner
            .conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        Ok(Box::new(QuinnControlStream { send, recv }))
    }

    async fn close(&self, error_code: u64) {
        let _ = self.inner.conn.close(
            quinn::VarInt::from_u64(error_code).unwrap_or(quinn::VarInt::from_u32(0)),
            b"connection closed",
        );
    }

    fn remote_addr(&self) -> SocketAddr {
        self.inner.conn.remote_address()
    }

    fn is_inbound(&self) -> bool {
        self.inner.conn.handshake_data().is_none()
    }

    fn clone_connection(&self) -> Box<dyn Connection> {
        Box::new(QuinnConnection {
            inner: self.inner.clone(),
        })
    }
}

// --- QuinnControlStream ---

struct QuinnControlStream {
    send: SendStream,
    recv: RecvStream,
}

#[async_trait]
impl ControlStream for QuinnControlStream {
    async fn send(&mut self, data: Bytes) -> TransportResult<()> {
        self.send
            .write_all(&data)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(())
    }

    async fn recv(&mut self) -> TransportResult<Option<Bytes>> {
        let mut buf = vec![0u8; 65536];
        match self.recv.read(&mut buf).await {
            Ok(Some(n)) => {
                buf.truncate(n);
                Ok(Some(Bytes::from(buf)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(TransportError::SendFailed(e.to_string())),
        }
    }

    async fn finish(&mut self) -> TransportResult<()> {
        self.send
            .finish()
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(())
    }
}

// --- QuinnListener ---

struct QuinnListener {
    endpoint: Endpoint,
}

#[async_trait]
impl Listener for QuinnListener {
    async fn accept(&self) -> TransportResult<(Box<dyn Connection>, SocketAddr)> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| TransportError::NotFound("no incoming connection".into()))?;
        let conn = incoming
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let addr = conn.remote_address();
        Ok((Box::new(QuinnConnection::new(conn)), addr))
    }

    fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr().unwrap()
    }
}

// --- Skip TLS verification (for testing/private networks) ---

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ensure_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn generate_self_signed_cert() -> (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        (cert_der, key_der)
    }

    #[tokio::test]
    async fn test_transport_connect_and_datagram() {
        ensure_crypto_provider();

        let (cert, key) = generate_self_signed_cert();

        let mut server_config =
            quinn::ServerConfig::with_single_cert(vec![cert], key.into()).unwrap();
        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_idle_timeout(Some(std::time::Duration::from_secs(5).try_into().unwrap()));
        server_config.transport_config(Arc::new(transport_config));

        let server = QuinnTransport::new_server(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            server_config,
        )
        .unwrap();
        let server_addr = server.local_addr();

        let client =
            QuinnTransport::new_client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .unwrap();

        let listener = server.listen(server_addr).await.unwrap();
        let client_conn = client.connect(server_addr).await.unwrap();

        // Send datagram client -> server
        let data = Bytes::from("hello quic");
        client_conn.send_datagram(data.clone()).await.unwrap();

        let (server_conn, _) = listener.accept().await.unwrap();
        let received = server_conn.recv_datagram().await.unwrap();
        assert_eq!(received, data);
    }
}
