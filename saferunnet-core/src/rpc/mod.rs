use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod server;
pub mod admin;
pub mod param_parser;
pub mod commands;
pub use server::RpcServer;

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 core types
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    pub id: u64,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorObj>,
    pub id: u64,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcErrorObj {
    pub code: i32,
    pub message: String,
}

impl RpcResponse {
    pub fn success(id: u64, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: u64, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(RpcErrorObj {
                code,
                message: message.into(),
            }),
            id,
        }
    }
}

// ---------------------------------------------------------------------------
// Domain types exposed via RPC
// ---------------------------------------------------------------------------

/// A node in the DHT routing table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoutingNode {
    /// Hex-encoded Ed25519 public key.
    pub public_key: String,
    /// "host:port" address.
    pub address: String,
    /// Unix timestamp of when this node was last seen.
    pub last_seen: u64,
}

/// Detailed peer connection information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerDetail {
    /// Hex-encoded identity public key.
    pub identity: String,
    /// Remote address string.
    pub address: String,
    /// Number of active link sessions.
    pub sessions: usize,
    /// Unix timestamp of when this peer connected.
    pub connected_since: u64,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("method not found: {0}")]
    MethodNotFound(String),
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Standard JSON-RPC error codes.
pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_request_serialize_deserialize() {
        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "status".into(),
            params: serde_json::Value::Null,
            id: 1,
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: RpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.method, "status");
        assert_eq!(decoded.id, 1);
    }

    #[test]
    fn rpc_response_success() {
        let resp = RpcResponse::success(2, serde_json::json!({"ok": true}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn rpc_response_error() {
        let resp = RpcResponse::error(3, -32601, "Method not found");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"error\""));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn rpc_request_missing_params_defaults_null() {
        let json = r#"{"jsonrpc":"2.0","method":"ping","id":1}"#;
        let req: RpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.params, serde_json::Value::Null);
    }

    #[test]
    fn routing_node_serialization() {
        let node = RoutingNode {
            public_key: "aabb1122".into(),
            address: "10.0.0.1:1090".into(),
            last_seen: 1700000000,
        };
        let json = serde_json::to_string(&node).unwrap();
        let decoded: RoutingNode = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, node);
    }

    #[test]
    fn peer_detail_serialization() {
        let peer = PeerDetail {
            identity: "aabb1122".into(),
            address: "10.0.0.2:1090".into(),
            sessions: 3,
            connected_since: 1699999999,
        };
        let json = serde_json::to_string(&peer).unwrap();
        let decoded: PeerDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, peer);
    }
}

// ---------------------------------------------------------------------------
// Oxen Chain RPC client (service node discovery)
// ---------------------------------------------------------------------------

pub mod oxen_client;
pub use oxen_client::{GetServiceNodesResponse, OxenRpcClient, OxenRpcError, ServiceNodeEntry};
