use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing;

use crate::error_codes;
use crate::{PeerDetail, RoutingNode, RpcRequest, RpcResponse};

/// An async JSON-RPC 2.0 admin server.
pub struct RpcServer {
    addr: SocketAddr,
    pub(crate) running: Arc<AtomicBool>,
    /// Peer count callback (injected by the kernel).
    peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
    /// Node state callback.
    node_state: Arc<dyn Fn() -> String + Send + Sync>,
    /// DHT routing table callback.
    routing_table_cb: Arc<dyn Fn() -> Vec<RoutingNode> + Send + Sync>,
    /// Detailed peer info callback.
    peers_detail_cb: Arc<dyn Fn() -> Vec<PeerDetail> + Send + Sync>,
    /// DHT lookup callback (by hex pubkey).
    dht_lookup_cb: Arc<dyn Fn(String) -> Vec<RoutingNode> + Send + Sync>,
}

impl RpcServer {
    /// Create a new RPC server bound to the given address.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            running: Arc::new(AtomicBool::new(false)),
            peer_count: Arc::new(|| 0),
            node_state: Arc::new(|| "unknown".into()),
            routing_table_cb: Arc::new(Vec::new),
            peers_detail_cb: Arc::new(Vec::new),
            dht_lookup_cb: Arc::new(|_| Vec::new()),
        }
    }

    /// Set a callback for peer count queries.
    pub fn with_peer_count<F: Fn() -> usize + Send + Sync + 'static>(mut self, f: F) -> Self {
        self.peer_count = Arc::new(f);
        self
    }

    /// Set a callback for node state queries.
    pub fn with_node_state<F: Fn() -> String + Send + Sync + 'static>(mut self, f: F) -> Self {
        self.node_state = Arc::new(f);
        self
    }

    /// Set a callback for DHT routing table queries.
    pub fn with_routing_table<F: Fn() -> Vec<RoutingNode> + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.routing_table_cb = Arc::new(f);
        self
    }

    /// Set a callback for detailed peer info queries.
    pub fn with_peers_detail<F: Fn() -> Vec<PeerDetail> + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.peers_detail_cb = Arc::new(f);
        self
    }

    /// Set a callback for DHT lookups by hex public key.
    pub fn with_dht_lookup<F: Fn(String) -> Vec<RoutingNode> + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.dht_lookup_cb = Arc::new(f);
        self
    }

    /// Start serving. Runs until `stop()` is called.
    pub async fn serve(&self) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(self.addr).await?;
        self.running.store(true, Ordering::SeqCst);
        tracing::info!(addr = %self.addr, "RPC server listening");

        let running = self.running.clone();
        let peer_count = self.peer_count.clone();
        let node_state = self.node_state.clone();
        let routing_table_cb = self.routing_table_cb.clone();
        let peers_detail_cb = self.peers_detail_cb.clone();
        let dht_lookup_cb = self.dht_lookup_cb.clone();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, remote)) => {
                            let pc = peer_count.clone();
                            let ns = node_state.clone();
                            let rt = routing_table_cb.clone();
                            let pd = peers_detail_cb.clone();
                            let dl = dht_lookup_cb.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, pc, ns, rt, pd, dl).await {
                                    tracing::warn!(%remote, error = %e, "RPC connection error");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "RPC accept error");
                        }
                    }
                }
                _ = async {
                    while running.load(Ordering::SeqCst) {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                } => {
                    break;
                }
            }
        }

        tracing::info!("RPC server stopped");
        Ok(())
    }

    /// Signal the server to stop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
    node_state: Arc<dyn Fn() -> String + Send + Sync>,
    routing_table_cb: Arc<dyn Fn() -> Vec<RoutingNode> + Send + Sync>,
    peers_detail_cb: Arc<dyn Fn() -> Vec<PeerDetail> + Send + Sync>,
    dht_lookup_cb: Arc<dyn Fn(String) -> Vec<RoutingNode> + Send + Sync>,
) -> Result<(), std::io::Error> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<RpcRequest>(&line) {
            Ok(req) => dispatch(
                &req,
                &peer_count,
                &node_state,
                &routing_table_cb,
                &peers_detail_cb,
                &dht_lookup_cb,
            ),
            Err(e) => RpcResponse::error(0, error_codes::PARSE_ERROR, &e.to_string()),
        };

        let mut json = serde_json::to_string(&response).unwrap_or_default();
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
    }

    Ok(())
}

fn dispatch(
    req: &RpcRequest,
    peer_count: &Arc<dyn Fn() -> usize + Send + Sync>,
    node_state: &Arc<dyn Fn() -> String + Send + Sync>,
    routing_table_cb: &Arc<dyn Fn() -> Vec<RoutingNode> + Send + Sync>,
    peers_detail_cb: &Arc<dyn Fn() -> Vec<PeerDetail> + Send + Sync>,
    dht_lookup_cb: &Arc<dyn Fn(String) -> Vec<RoutingNode> + Send + Sync>,
) -> RpcResponse {
    match req.method.as_str() {
        "status" => {
            let state = node_state();
            let peers = peer_count();
            RpcResponse::success(
                req.id,
                serde_json::json!({
                    "state": state,
                    "peer_count": peers,
                }),
            )
        }
        "peers" => RpcResponse::success(
            req.id,
            serde_json::json!({
                "peers": [],
                "count": peer_count(),
            }),
        ),
        "routing_table" => {
            let nodes = routing_table_cb();
            RpcResponse::success(
                req.id,
                serde_json::json!({
                    "nodes": nodes,
                    "count": nodes.len(),
                }),
            )
        }
        "peers_detail" => {
            let peers = peers_detail_cb();
            RpcResponse::success(
                req.id,
                serde_json::json!({
                    "peers": peers,
                    "count": peers.len(),
                }),
            )
        }
        "dht_lookup" => {
            let target = req
                .params
                .get("target")
                .and_then(|v| v.as_str())
                .map(String::from);
            match target {
                Some(t) => {
                    let nodes = dht_lookup_cb(t);
                    RpcResponse::success(req.id, serde_json::json!({ "nodes": nodes }))
                }
                None => RpcResponse::error(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "missing 'target' parameter",
                ),
            }
        }
        "stop" => RpcResponse::success(req.id, serde_json::json!({"stopping": true})),
        unknown => RpcResponse::error(
            req.id,
            error_codes::METHOD_NOT_FOUND,
            &format!("unknown method: {unknown}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    async fn find_free_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn rpc_server_status() {
        let addr = find_free_addr().await;
        let server = RpcServer::new(addr)
            .with_node_state(|| "running".into())
            .with_peer_count(|| 5);

        let stop = server.running.clone();
        tokio::spawn(async move { server.serve().await.unwrap() });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","method":"status","params":null,"id":1}"#;
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: RpcResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(resp.id, 1);
        let result = resp.result.unwrap();
        assert_eq!(result["state"], "running");
        assert_eq!(result["peer_count"], 5);

        stop.store(false, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn rpc_server_unknown_method() {
        let addr = find_free_addr().await;
        let server = RpcServer::new(addr);

        let stop = server.running.clone();
        tokio::spawn(async move { server.serve().await.unwrap() });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","method":"nonexistent","params":null,"id":42}"#;
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: RpcResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(resp.id, 42);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, error_codes::METHOD_NOT_FOUND);

        stop.store(false, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn rpc_server_stop_command() {
        let addr = find_free_addr().await;
        let server = RpcServer::new(addr);

        let stop = server.running.clone();
        tokio::spawn(async move { server.serve().await.unwrap() });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","method":"stop","params":null,"id":7}"#;
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: RpcResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(resp.id, 7);
        assert!(resp.result.is_some());

        stop.store(false, Ordering::SeqCst);
    }

    // ─── New method tests ───

    #[tokio::test]
    async fn rpc_routing_table() {
        let addr = find_free_addr().await;
        let server = RpcServer::new(addr).with_routing_table(|| {
            vec![RoutingNode {
                public_key: "ab".repeat(32),
                address: "10.0.0.1:1090".into(),
                last_seen: 1000,
            }]
        });

        let stop = server.running.clone();
        tokio::spawn(async move { server.serve().await.unwrap() });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","method":"routing_table","params":null,"id":10}"#;
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: RpcResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(resp.id, 10);
        let result = resp.result.unwrap();
        assert_eq!(result["count"], 1);
        assert_eq!(result["nodes"][0]["address"], "10.0.0.1:1090");

        stop.store(false, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn rpc_peers_detail() {
        let addr = find_free_addr().await;
        let server = RpcServer::new(addr).with_peers_detail(|| {
            vec![PeerDetail {
                identity: "cd".repeat(32),
                address: "10.0.0.2:1090".into(),
                sessions: 3,
                connected_since: 500,
            }]
        });

        let stop = server.running.clone();
        tokio::spawn(async move { server.serve().await.unwrap() });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","method":"peers_detail","params":null,"id":11}"#;
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: RpcResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(resp.id, 11);
        let result = resp.result.unwrap();
        assert_eq!(result["count"], 1);
        assert_eq!(result["peers"][0]["sessions"], 3);

        stop.store(false, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn rpc_dht_lookup_success() {
        let addr = find_free_addr().await;
        let server = RpcServer::new(addr).with_dht_lookup(|t| {
            vec![RoutingNode {
                public_key: t,
                address: "10.0.0.3:1090".into(),
                last_seen: 2000,
            }]
        });

        let stop = server.running.clone();
        tokio::spawn(async move { server.serve().await.unwrap() });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req =
            r#"{"jsonrpc":"2.0","method":"dht_lookup","params":{"target":"deadbeef"},"id":12}"#;
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: RpcResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(resp.id, 12);
        let result = resp.result.unwrap();
        assert_eq!(result["nodes"][0]["public_key"], "deadbeef");

        stop.store(false, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn rpc_dht_lookup_missing_params() {
        let addr = find_free_addr().await;
        let server = RpcServer::new(addr);

        let stop = server.running.clone();
        tokio::spawn(async move { server.serve().await.unwrap() });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","method":"dht_lookup","params":null,"id":13}"#;
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: RpcResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(resp.id, 13);
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, error_codes::INVALID_PARAMS);
        assert!(err.message.contains("target"));

        stop.store(false, Ordering::SeqCst);
    }
}
