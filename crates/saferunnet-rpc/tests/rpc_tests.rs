use saferunnet_rpc::RpcServer;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

async fn find_free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

#[tokio::test]
async fn rpc_status_returns_state_and_peers() {
    let addr = find_free_addr().await;
    let server = RpcServer::new(addr)
        .with_node_state(|| "Running".into())
        .with_peer_count(|| 3);

    let handle = tokio::spawn(async move { server.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"status\",\"params\":null,\"id\":1}\n")
        .await
        .unwrap();

    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let resp: saferunnet_rpc::RpcResponse = serde_json::from_str(&line).unwrap();
    assert_eq!(resp.id, 1);
    let result = resp.result.unwrap();
    assert_eq!(result["state"], "Running");
    assert_eq!(result["peer_count"], 3);

    handle.abort();
}

#[tokio::test]
async fn rpc_peers_returns_list() {
    let addr = find_free_addr().await;
    let server = RpcServer::new(addr).with_peer_count(|| 7);

    let handle = tokio::spawn(async move { server.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"peers\",\"params\":null,\"id\":2}\n")
        .await
        .unwrap();

    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let resp: saferunnet_rpc::RpcResponse = serde_json::from_str(&line).unwrap();
    let result = resp.result.unwrap();
    assert_eq!(result["count"], 7);

    handle.abort();
}

#[tokio::test]
async fn rpc_stop_returns_acknowledged() {
    let addr = find_free_addr().await;
    let server = RpcServer::new(addr);

    let handle = tokio::spawn(async move { server.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"stop\",\"params\":null,\"id\":3}\n")
        .await
        .unwrap();

    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let resp: saferunnet_rpc::RpcResponse = serde_json::from_str(&line).unwrap();
    assert_eq!(resp.id, 3);
    assert!(resp.result.is_some());

    handle.abort();
}

#[tokio::test]
async fn rpc_unknown_method_returns_error() {
    let addr = find_free_addr().await;
    let server = RpcServer::new(addr);

    let handle = tokio::spawn(async move { server.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"nonexistent\",\"params\":null,\"id\":4}\n")
        .await
        .unwrap();

    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let resp: saferunnet_rpc::RpcResponse = serde_json::from_str(&line).unwrap();
    assert_eq!(resp.id, 4);
    assert!(resp.error.is_some());
    assert_eq!(
        resp.error.unwrap().code,
        saferunnet_rpc::error_codes::METHOD_NOT_FOUND
    );

    handle.abort();
}
