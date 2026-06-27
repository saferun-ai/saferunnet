# SaferunNet Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite SaferunNet from 18 fragmented crates into 6 well-architected crates with QUIC transport, Oxen chain node discovery, and full observability.

**Architecture:** Merge 12 core-logic crates into `saferunnet-core` with physical directory structure. Replace raw UDP transport with QUIC (quinn). Build full spdlog-level logging system. Add 8 new modules ported from Lokinet C++ (handlers, net, auth, consensus, contact, encoding, address, constants).

**Tech Stack:** Rust 2024, tokio, quinn, tracing, clap, serde, zmq.rs, ed25519-dalek, x25519-dalek

**Design Spec:** `docs/superpowers/specs/2026-06-27-saferunnet-architecture-design.md`

---

## Phase 0: Crate Merge (18 → 6)

### Task 0.1: Flatten workspace and create new crate skeleton

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Create: `saferunnet-core/Cargo.toml`
- Create: `saferunnet-core/src/lib.rs`
- Create: `saferunnet-core/src/router/mod.rs`
- Create: `saferunnet-core/src/path/mod.rs`
- Create: `saferunnet-core/src/dns/mod.rs`
- Create: `saferunnet-core/src/session/mod.rs`
- Create: `saferunnet-core/src/config/mod.rs`
- Create: `saferunnet-core/src/vpn/mod.rs`
- Create: `saferunnet-core/src/dht/mod.rs`
- Create: `saferunnet-core/src/rpc/mod.rs`
- Create: `saferunnet-core/src/handlers/mod.rs`
- Create: `saferunnet-core/src/net/mod.rs`
- Create: `saferunnet-core/src/auth/mod.rs`
- Create: `saferunnet-core/src/consensus/mod.rs`
- Create: `saferunnet-core/src/contact/mod.rs`
- Create: `saferunnet-core/src/encoding/mod.rs`
- Create: `saferunnet-core/src/address/mod.rs`
- Create: `saferunnet-core/src/constants/mod.rs`
- Create: `saferunnet-transport/src/quic.rs`
- Create: `saferunnet-transport/src/link.rs`
- Create: `saferunnet-transport/src/event.rs`
- Create: `saferunnet-transport/src/tcp_tunnel.rs`
- Create: `saferunnet-transport/src/traits.rs`
- Create: `saferunnet-observability/src/sink.rs`
- Create: `saferunnet-observability/src/category.rs`
- Create: `saferunnet-observability/src/ringbuf.rs`
- Create: `saferunnet-observability/src/callback.rs`
- Create: `saferunnet-observability/src/config.rs`
- Create: `saferunnet-observability/src/init.rs`
- Create: `saferunnet/src/main.rs`
- Delete: `crates/` directory (all 18 old crates)

- [ ] **Step 1: Update workspace Cargo.toml**

```toml
[workspace]
resolver = "2"
members = [
    "saferunnet-core",
    "saferunnet-crypto",
    "saferunnet-transport",
    "saferunnet-platform",
    "saferunnet-observability",
    "saferunnet",
]

[workspace.package]
version = "0.2.0"
edition = "2021"
license = "MIT"

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
quinn = "0.11"
zmq = "0.10"
ed25519-dalek = "2"
x25519-dalek = "2"
rand = "0.8"
thiserror = "2"
bytes = "1"
parking_lot = "0.12"
```

- [ ] **Step 2: Create saferunnet-core/Cargo.toml**

```toml
[package]
name = "saferunnet-core"
version.workspace = true
edition.workspace = true

[dependencies]
saferunnet-crypto = { path = "../saferunnet-crypto" }
saferunnet-transport = { path = "../saferunnet-transport" }
saferunnet-observability = { path = "../saferunnet-observability" }
tokio.workspace = true
tracing.workspace = true
serde.workspace = true
serde_json.workspace = true
ed25519-dalek.workspace = true
rand.workspace = true
thiserror.workspace = true
bytes.workspace = true
parking_lot.workspace = true
```

- [ ] **Step 3: Create saferunnet-core/src/lib.rs with module declarations**

```rust
pub mod address;
pub mod auth;
pub mod config;
pub mod consensus;
pub mod constants;
pub mod contact;
pub mod dht;
pub mod dns;
pub mod encoding;
pub mod handlers;
pub mod net;
pub mod path;
pub mod router;
pub mod rpc;
pub mod session;
pub mod vpn;
```

- [ ] **Step 4: Create saferunnet-transport/Cargo.toml**

```toml
[package]
name = "saferunnet-transport"
version.workspace = true
edition.workspace = true

[dependencies]
saferunnet-platform = { path = "../saferunnet-platform" }
quinn.workspace = true
tokio.workspace = true
tracing.workspace = true
thiserror.workspace = true
bytes.workspace = true
rand.workspace = true
```

- [ ] **Step 5: Update saferunnet-transport/src/lib.rs**

```rust
pub mod quic;
pub mod link;
pub mod event;
pub mod tcp_tunnel;
pub mod traits;
```

- [ ] **Step 6: Create saferunnet-observability/Cargo.toml**

```toml
[package]
name = "saferunnet-observability"
version.workspace = true
edition.workspace = true

[dependencies]
tracing.workspace = true
tracing-subscriber.workspace = true
serde.workspace = true
parking_lot.workspace = true
thiserror.workspace = true
```

- [ ] **Step 7: Create saferunnet/Cargo.toml (binary)**

```toml
[package]
name = "saferunnet"
version.workspace = true
edition.workspace = true

[[bin]]
name = "saferunnet"
path = "src/main.rs"

[dependencies]
saferunnet-core = { path = "../saferunnet-core" }
saferunnet-crypto = { path = "../saferunnet-crypto" }
saferunnet-transport = { path = "../saferunnet-transport" }
saferunnet-platform = { path = "../saferunnet-platform" }
saferunnet-observability = { path = "../saferunnet-observability" }
clap.workspace = true
tokio.workspace = true
tracing.workspace = true
```

- [ ] **Step 8: Delete old crates/ directory**

```powershell
Remove-Item -Recurse -Force crates/
```

- [ ] **Step 9: Verify build structure**

```bash
cargo check --workspace
```

Expected: All crates resolve, no compilation errors (modules are empty).

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "refactor: flatten workspace 18->6 crates, create module skeletons"
```

---

### Task 0.2: Migrate crypto crate (no dependencies, clean move)

**Files:**
- Keep: `saferunnet-crypto/` (already at root level, no changes needed if paths correct)
- Verify: `saferunnet-crypto/Cargo.toml` uses workspace dependencies

- [ ] **Step 1: Check current crypto crate location and update Cargo.toml if needed**

```bash
cargo check -p saferunnet-crypto
```

- [ ] **Step 2: Commit**

```bash
git add saferunnet-crypto/
git commit -m "refactor: verify and fix saferunnet-crypto for new workspace"
```

---

### Task 0.3: Migrate platform crate

**Files:**
- Keep: `saferunnet-platform/` (already at root level)

- [ ] **Step 1: Update saferunnet-platform/Cargo.toml to workspace deps**

```toml
[package]
name = "saferunnet-platform"
version.workspace = true
edition.workspace = true

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.59", features = ["Win32_NetworkManagement_IpHelper", "Win32_Networking_WinSock"] }

[dependencies]
tracing.workspace = true
thiserror.workspace = true
```

- [ ] **Step 2: Verify**

```bash
cargo check -p saferunnet-platform
```

- [ ] **Step 3: Commit**

---

### Task 0.4: Merge core logic crates into saferunnet-core

**Source → Target mapping (files to move):**

```
saferunnet-router/src/   → saferunnet-core/src/router/
saferunnet-path/src/     → saferunnet-core/src/path/
saferunnet-dns/src/      → saferunnet-core/src/dns/
saferunnet-session/src/  → saferunnet-core/src/session/
saferunnet-config/src/   → saferunnet-core/src/config/
saferunnet-dht/src/      → saferunnet-core/src/dht/
saferunnet-exit/src/     → saferunnet-core/src/vpn/
saferunnet-rpc/src/      → saferunnet-core/src/rpc/
saferunnet-service/src/  → (split into: router, path, session, dht submodules)
saferunnet-identity/src/ → saferunnet-core/src/contact/
saferunnet-compat-lokinet/src/ → saferunnet-core/src/config/ (merge parser)
```

- [ ] **Step 1: Move router module**

```powershell
Copy-Item -Recurse crates/saferunnet-router/src/* saferunnet-core/src/router/
```

- [ ] **Step 2: Move path module**

```powershell
Copy-Item -Recurse crates/saferunnet-path/src/* saferunnet-core/src/path/
```

- [ ] **Step 3: Move dns module**

```powershell
Copy-Item -Recurse crates/saferunnet-dns/src/* saferunnet-core/src/dns/
```

- [ ] **Step 4: Move session module**

```powershell
Copy-Item -Recurse crates/saferunnet-app/src/session.rs saferunnet-core/src/session/
```

- [ ] **Step 5: Move config module**

```powershell
Copy-Item -Recurse crates/saferunnet-config/src/* saferunnet-core/src/config/
```

- [ ] **Step 6: Move dht module**

```powershell
Copy-Item -Recurse crates/saferunnet-dht/src/* saferunnet-core/src/dht/
```

- [ ] **Step 7: Move vpn module**

```powershell
Copy-Item -Recurse crates/saferunnet-exit/src/* saferunnet-core/src/vpn/
```

- [ ] **Step 8: Move rpc module**

```powershell
Copy-Item -Recurse crates/saferunnet-rpc/src/* saferunnet-core/src/rpc/
```

- [ ] **Step 9: Move service messages into appropriate submodules**

```powershell
Copy-Item crates/saferunnet-service/src/link_message.rs saferunnet-core/src/
Copy-Item crates/saferunnet-service/src/session_*.rs saferunnet-core/src/session/
Copy-Item crates/saferunnet-service/src/path_*.rs saferunnet-core/src/path/
Copy-Item crates/saferunnet-service/src/transit_hop.rs saferunnet-core/src/path/
```

- [ ] **Step 10: Move identity → contact**

```powershell
Copy-Item crates/saferunnet-identity/src/* saferunnet-core/src/contact/
```

- [ ] **Step 11: Fix all internal use/crate references**

Run and fix errors iteratively:
```bash
cargo check -p saferunnet-core 2>&1 | head -50
```

All `use saferunnet_router::` → `use crate::router::`
All `use saferunnet_path::` → `use crate::path::`
All `use saferunnet_dns::` → `use crate::dns::`
All `use saferunnet_session::` → `use crate::session::`
All `use saferunnet_config::` → `use crate::config::`
All `use saferunnet_dht::` → `use crate::dht::`
All `use saferunnet_exit::` → `use crate::vpn::`
All `use saferunnet_rpc::` → `use crate::rpc::`
All `use saferunnet_service::` → `use crate::<appropriate_submodule>::`
All `use saferunnet_identity::` → `use crate::contact::`
All `use saferunnet_compat_lokinet::` → `use crate::config::`

- [ ] **Step 12: Iterate cargo check until clean**

```bash
cargo check -p saferunnet-core
cargo check --workspace
```

- [ ] **Step 13: Commit**

---

### Task 0.5: Merge transport + link into saferunnet-transport

- [ ] **Step 1: Move link module**

```powershell
Copy-Item -Recurse crates/saferunnet-link/src/* saferunnet-transport/src/link/
```

- [ ] **Step 2: Move transport module**

```powershell
Copy-Item crates/saferunnet-transport/src/transport.rs saferunnet-transport/src/
Copy-Item crates/saferunnet-transport/src/session.rs saferunnet-transport/src/
Copy-Item crates/saferunnet-transport/src/handshake.rs saferunnet-transport/src/
```

- [ ] **Step 3: Fix internal references**

All `use saferunnet_link::` → `use crate::link::`
All `use saferunnet_transport::` → `use crate::`

- [ ] **Step 4: Verify**

```bash
cargo check -p saferunnet-transport
```

- [ ] **Step 5: Commit**

---

### Task 0.6: Migrate app/binary into saferunnet/

- [ ] **Step 1: Move main.rs**

```powershell
Copy-Item crates/saferunnet-app/src/main.rs saferunnet/src/main.rs
```

- [ ] **Step 2: Move supporting files**

```powershell
Copy-Item crates/saferunnet-app/src/dns.rs saferunnet/src/
Copy-Item crates/saferunnet-app/src/identity.rs saferunnet/src/
Copy-Item crates/saferunnet-app/src/kernel.rs saferunnet/src/
Copy-Item crates/saferunnet-app/src/link.rs saferunnet/src/
Copy-Item crates/saferunnet-app/src/path.rs saferunnet/src/
```

- [ ] **Step 3: Fix use statements to new crate names**

All `use saferunnet_app::` → local module references
All `use saferunnet_core::` → `use saferunnet_core::` (unchanged)

- [ ] **Step 4: Verify full workspace build**

```bash
cargo check --workspace
cargo build --release
```

- [ ] **Step 5: Run all tests**

```bash
cargo test --workspace
```

- [ ] **Step 6: Run quality gates**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor: complete Phase 0 - 18 crates merged into 6"
```

---

## Phase 1: Transport Rewrite (UDP → QUIC)

### Task 1.1: Define TransportLayer trait

**Files:**
- Create: `saferunnet-transport/src/traits.rs`

- [ ] **Step 1: Write trait definition**

```rust
use std::net::SocketAddr;
use async_trait::async_trait;
use bytes::Bytes;

/// Result type for transport operations
pub type TransportResult<T> = Result<T, TransportError>;

/// Transport layer errors
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("not found: {0}")]
    NotFound(String),
}

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
```

- [ ] **Step 2: Add async-trait to workspace deps**

```toml
# In workspace Cargo.toml
async-trait = "0.1"
```

- [ ] **Step 3: Verify compilation**

```bash
cargo check -p saferunnet-transport
```

- [ ] **Step 4: Commit**

---

### Task 1.2: Implement QUIC transport with quinn

**Files:**
- Create: `saferunnet-transport/src/quic.rs`

- [ ] **Step 1: Write QuinnTransport implementation**

```rust
use std::net::SocketAddr;
use std::sync::Arc;
use async_trait::async_trait;
use bytes::Bytes;
use quinn::{Endpoint, Connection as QuinnConn, SendStream, RecvStream};
use tokio::sync::Mutex;
use crate::traits::*;

/// QUIC-based transport layer using quinn.
/// Lokinet C++ equivalent: oxen-libquic
pub struct QuinnTransport {
    endpoint: Endpoint,
}

impl QuinnTransport {
    pub fn new(bind_addr: SocketAddr) -> TransportResult<Self> {
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));

        let mut server_config = quinn::ServerConfig::with_single_cert(
            vec![], // TODO: generate self-signed cert
            vec![], // TODO: generate key
        ).map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let endpoint = Endpoint::server(server_config, bind_addr)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        Ok(Self { endpoint })
    }

    pub fn new_client(bind_addr: SocketAddr) -> TransportResult<Self> {
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(SkipVerification))
                    .with_no_client_auth(),
            ).unwrap(),
        ));

        let mut endpoint = Endpoint::client(bind_addr)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }
}

#[async_trait]
impl TransportLayer for QuinnTransport {
    async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn Connection>> {
        let connection = self.endpoint
            .connect(addr, "localhost")
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        Ok(Box::new(QuinnConnection::new(connection)))
    }

    async fn listen(&self, addr: SocketAddr) -> TransportResult<Box<dyn Listener>> {
        // Already listening on self.endpoint
        Ok(Box::new(QuinnListener { endpoint: self.endpoint.clone() }))
    }
}

struct QuinnConnection {
    conn: QuinnConn,
    datagram_tx: tokio::sync::mpsc::Sender<Bytes>,
    datagram_rx: Mutex<tokio::sync::mpsc::Receiver<Bytes>>,
}

impl QuinnConnection {
    fn new(conn: QuinnConn) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let conn_clone = conn.clone();
        tokio::spawn(async move {
            while let Ok(datagram) = conn_clone.read_datagram().await {
                if tx.send(Bytes::from(datagram)).await.is_err() {
                    break;
                }
            }
        });
        Self { conn, datagram_tx: tx, datagram_rx: Mutex::new(rx) }
    }
}

#[async_trait]
impl Connection for QuinnConnection {
    async fn send_datagram(&self, data: Bytes) -> TransportResult<()> {
        self.conn.send_datagram(data.into())
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(())
    }

    async fn recv_datagram(&self) -> TransportResult<Bytes> {
        self.datagram_rx.lock().await.recv().await
            .ok_or_else(|| TransportError::NotFound("datagram channel closed".into()))
    }

    async fn open_stream(&self) -> TransportResult<Box<dyn ControlStream>> {
        let (send, recv) = self.conn.open_bi()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        Ok(Box::new(QuinnControlStream { send, recv }))
    }

    async fn accept_stream(&self) -> TransportResult<Box<dyn ControlStream>> {
        let (send, recv) = self.conn.accept_bi()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        Ok(Box::new(QuinnControlStream { send, recv }))
    }

    async fn close(&self, error_code: u64) {
        let _ = self.conn.close(
            quinn::VarInt::from_u64(error_code),
            b"connection closed",
        );
    }

    fn remote_addr(&self) -> SocketAddr { self.conn.remote_address() }
    fn is_inbound(&self) -> bool { self.conn.handshake_data().is_none() }
}

struct QuinnControlStream {
    send: SendStream,
    recv: RecvStream,
}

#[async_trait]
impl ControlStream for QuinnControlStream {
    async fn send(&mut self, data: Bytes) -> TransportResult<()> {
        self.send.write_all(&data).await
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
        self.send.finish().await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(())
    }
}

struct QuinnListener {
    endpoint: Endpoint,
}

#[async_trait]
impl Listener for QuinnListener {
    async fn accept(&self) -> TransportResult<(Box<dyn Connection>, SocketAddr)> {
        let incoming = self.endpoint.accept().await
            .ok_or_else(|| TransportError::NotFound("no incoming connection".into()))?;
        let conn = incoming.await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let addr = conn.remote_address();
        Ok((Box::new(QuinnConnection::new(conn)), addr))
    }

    fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr().unwrap()
    }
}

/// Skip TLS verification (for testing/private networks)
struct SkipVerification;
impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self, _: &rustls::pki_types::CertificateDer,
        _: &[rustls::pki_types::CertificateDer],
        _: &rustls::pki_types::ServerName,
        _: &[u8], _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &dyn sign::Signer)
        -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &dyn sign::Signer)
        -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::RSA_PKCS1_SHA256]
    }
}
```

- [ ] **Step 2: Add rustls dependency**

```toml
# In workspace Cargo.toml
rustls = { version = "0.23", default-features = false, features = ["ring"] }
```

- [ ] **Step 3: Verify compilation**

```bash
cargo check -p saferunnet-transport
```

- [ ] **Step 4: Write unit test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_transport_connect_listen() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = QuinnTransport::new(addr).unwrap();
        let client = QuinnTransport::new_client("127.0.0.1:0".parse().unwrap()).unwrap();

        let server_addr = server.endpoint.local_addr().unwrap();
        let listener = server.listen(server_addr).await.unwrap();
        let client_conn = client.connect(server_addr).await.unwrap();

        // Send datagram client -> server
        let data = Bytes::from("hello from client");
        client_conn.send_datagram(data.clone()).await.unwrap();

        let (server_conn, _) = listener.accept().await.unwrap();
        let received = server_conn.recv_datagram().await.unwrap();
        assert_eq!(received, data);
    }
}
```

- [ ] **Step 5: Run test**

```bash
cargo test -p saferunnet-transport -- --nocapture
```

- [ ] **Step 6: Commit**

---

### Task 1.3: Rewrite LinkManager to use TransportLayer trait

**Files:**
- Create: `saferunnet-transport/src/link.rs`

- [ ] **Step 1: Write LinkManager**

```rust
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use parking_lot::RwLock;
use crate::traits::*;

/// Manages QUIC connections to remote Lokinet routers.
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

    pub async fn connect(&self, addr: SocketAddr) -> TransportResult<()> {
        let conn = self.transport.connect(addr).await?;
        self.connections.write().insert(addr, conn);
        Ok(())
    }

    pub async fn send_data_message(&self, addr: SocketAddr, data: bytes::Bytes) -> TransportResult<()> {
        let conn = self.connections.read()
            .get(&addr)
            .ok_or_else(|| TransportError::NotFound(format!("no connection to {}", addr)))?
            .clone_connection();
        conn.send_datagram(data).await
    }

    pub async fn send_control_message(&self, addr: SocketAddr, data: bytes::Bytes) -> TransportResult<bytes::Bytes> {
        let conn = self.connections.read()
            .get(&addr)
            .ok_or_else(|| TransportError::NotFound(format!("no connection to {}", addr)))?
            .clone_connection();
        let mut stream = conn.open_stream().await?;
        stream.send(data).await?;
        stream.finish().await?;
        stream.recv().await?
            .ok_or_else(|| TransportError::NotFound("empty response".into()))
    }

    pub fn close_connection(&self, addr: &SocketAddr) {
        if let Some(conn) = self.connections.write().remove(addr) {
            tokio::spawn(async move { conn.inner.close(0).await });
        }
    }

    pub fn have_connection_to(&self, addr: &SocketAddr) -> bool {
        self.connections.read().contains_key(addr)
    }
}
```

Note: This requires a `clone_connection()` method on the trait or inner Arc wrapping. Adjust trait if needed:

```rust
// Add to Connection trait:
fn clone_connection(&self) -> Box<dyn Connection>;
```

- [ ] **Step 2: Verify compilation**

```bash
cargo check -p saferunnet-transport
```

- [ ] **Step 3: Write integration test with mock transport**

- [ ] **Step 4: Run tests**

```bash
cargo test -p saferunnet-transport
```

- [ ] **Step 5: Commit**

---

### Task 1.4: Implement TCP-over-QUIC tunnel

**Files:**
- Create: `saferunnet-transport/src/tcp_tunnel.rs`

- [ ] **Step 1: Write QUICTunnel**

```rust
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::Bytes;
use crate::traits::{Connection, ControlStream, TransportResult};

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
        Self { quic_conn, local_port }
    }

    /// Start listening on a local TCP port and tunnel all connections
    pub async fn listen_and_serve(self) -> TransportResult<()> {
        let listener = TcpListener::bind(("127.0.0.1", self.local_port)).await
            .map_err(|e| crate::traits::TransportError::ConnectionFailed(e.to_string()))?;

        loop {
            let (tcp_stream, _addr) = listener.accept().await
                .map_err(|e| crate::traits::TransportError::ConnectionFailed(e.to_string()))?;

            let conn = self.quic_conn.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_tcp_connection(conn, tcp_stream).await {
                    tracing::warn!("TCP tunnel stream error: {}", e);
                }
            });
        }
    }

    async fn handle_tcp_connection(conn: Arc<dyn Connection>, mut tcp: TcpStream) -> TransportResult<()> {
        let mut quic_stream = conn.open_stream().await?;

        let (mut tcp_read, mut tcp_write) = tcp.split();

        // TCP → QUIC
        let mut quic_send = quic_stream; // ownership transfer
        let send_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let n = tcp_read.read(&mut buf).await?;
                if n == 0 { break; }
                quic_send.send(Bytes::from(buf[..n].to_vec())).await?;
            }
            quic_send.finish().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        // QUIC → TCP (needs separate stream accept on remote side)
        let _ = send_handle.await;
        Ok(())
    }
}
```

- [ ] **Step 2: Verify compilation**

- [ ] **Step 3: Commit**

---

## Phase 2: Observability Rewrite

### Task 2.1: Implement LoggingConfig

**Files:**
- Create: `saferunnet-observability/src/config.rs`

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Log output type.
/// Lokinet C++ equivalent: log::Type enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogType {
    Print,
    File,
    System,
}

/// Logging configuration section.
/// Lokinet C++ equivalent: llarp/config/config.hpp LoggingConfig
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(rename = "type")]
    pub log_type: Option<LogType>,
    pub file: Option<String>,
    pub levels: HashMap<String, String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_type: Some(LogType::Print),
            file: None,
            levels: HashMap::from([
                ("router".into(), "info".into()),
                ("crypto".into(), "warn".into()),
                ("transport".into(), "info".into()),
                ("dns".into(), "info".into()),
                ("path".into(), "debug".into()),
                ("session".into(), "info".into()),
            ]),
        }
    }
}
```

### Task 2.2: Implement multi-sink initialization

- Create: `saferunnet-observability/src/init.rs`
- Create: `saferunnet-observability/src/sink.rs`
- Create: `saferunnet-observability/src/category.rs`

(Detailed code as in design spec)
```

...
