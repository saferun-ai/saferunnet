use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

/// A single service node entry from oxend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceNodeEntry {
    pub pubkey_ed25519: String,
    pub service_node_pubkey: String,
    pub funded: bool,
    pub active: bool,
    #[serde(default)]
    pub block_hash: String,
}

/// Response from the `rpc.get_service_nodes` oxend RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetServiceNodesResponse {
    pub status: String,
    #[serde(default)]
    pub unchanged: Option<bool>,
    #[serde(default)]
    pub service_node_states: Vec<ServiceNodeEntry>,
    #[serde(default)]
    pub block_hash: Option<String>,
}

/// Oxen chain RPC client for node discovery.
/// Lokinet C++ equivalent: llarp/rpc/rpc_client.hpp RPCClient
pub struct OxenRpcClient {
    oxend_url: String,
    is_updating: AtomicBool,
    last_hash_update: parking_lot::Mutex<String>,
    known_nodes: parking_lot::RwLock<Vec<ServiceNodeEntry>>,
}

impl OxenRpcClient {
    pub fn new(oxend_url: String) -> Self {
        Self {
            oxend_url,
            is_updating: AtomicBool::new(false),
            last_hash_update: parking_lot::Mutex::new(String::new()),
            known_nodes: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Fetch the service node list from oxend.
    /// Returns true if the list was updated, false if unchanged or failed.
    pub async fn update_service_node_list(&self) -> Result<bool, OxenRpcError> {
        if self.is_updating.swap(true, Ordering::AcqRel) {
            return Ok(false); // Update already in progress
        }

        let result = self.fetch_from_oxend().await;

        self.is_updating.store(false, Ordering::Release);
        result
    }

    async fn fetch_from_oxend(&self) -> Result<bool, OxenRpcError> {
        // Build the JSON-RPC-like request that oxend expects
        let mut request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "rpc.get_service_nodes",
            "params": {
                "fields": {
                    "pubkey_ed25519": true,
                    "service_node_pubkey": true,
                    "funded": true,
                    "active": true,
                    "block_hash": true,
                }
            },
            "id": 1,
        });

        // Add poll_block_hash for incremental updates
        {
            let hash = self.last_hash_update.lock();
            if !hash.is_empty() {
                request["params"]["poll_block_hash"] = serde_json::Value::String(hash.clone());
            }
        }

        // Send HTTP request to oxend
        let client = reqwest::Client::new();
        let response = client
            .post(&self.oxend_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| OxenRpcError::ConnectionFailed(e.to_string()))?;

        let raw: serde_json::Value = response
            .json()
            .await
            .map_err(|e| OxenRpcError::ParseFailed(e.to_string()))?;

        let result = raw
            .get("result")
            .ok_or_else(|| OxenRpcError::ParseFailed("missing ''result'' field".into()))?;

        // Check if unchanged
        if let Some(unchanged) = result.get("unchanged").and_then(|v| v.as_bool()) {
            if unchanged {
                tracing::trace!("service node list unchanged");
                return Ok(false);
            }
        }

        // Parse the result
        let sn_response: GetServiceNodesResponse = serde_json::from_value(result.clone())
            .map_err(|e| OxenRpcError::ParseFailed(e.to_string()))?;

        // Update the known nodes list
        let nodes = sn_response.service_node_states.clone();
        self.handle_new_service_node_list(nodes).await;

        // Update last hash for polling
        if let Some(hash) = sn_response.block_hash {
            *self.last_hash_update.lock() = hash;
        }

        Ok(true)
    }

    async fn handle_new_service_node_list(&self, nodes: Vec<ServiceNodeEntry>) {
        let active_nodes: Vec<_> = nodes.into_iter().filter(|n| n.active).collect();
        tracing::info!(
            "Updated service node list: {} total, {} active",
            active_nodes.len(),
            active_nodes.iter().filter(|n| n.funded).count(),
        );
        *self.known_nodes.write() = active_nodes;
    }

    /// Get the current active service nodes
    pub fn get_active_nodes(&self) -> Vec<ServiceNodeEntry> {
        self.known_nodes.read().clone()
    }

    /// Get only funded + active service nodes
    pub fn get_funded_active_nodes(&self) -> Vec<ServiceNodeEntry> {
        self.known_nodes
            .read()
            .iter()
            .filter(|n| n.funded && n.active)
            .cloned()
            .collect()
    }

    /// Get the ed25519 pubkeys of all active nodes
    pub fn get_active_pubkeys(&self) -> Vec<String> {
        self.known_nodes
            .read()
            .iter()
            .filter(|n| n.active)
            .map(|n| n.pubkey_ed25519.clone())
            .collect()
    }

    /// Get the x25519 pubkeys of all active nodes
    pub fn get_active_service_pubkeys(&self) -> Vec<String> {
        self.known_nodes
            .read()
            .iter()
            .filter(|n| n.active)
            .map(|n| n.service_node_pubkey.clone())
            .collect()
    }

    /// Number of known active nodes
    pub fn active_count(&self) -> usize {
        self.known_nodes.read().iter().filter(|n| n.active).count()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OxenRpcError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("parse failed: {0}")]
    ParseFailed(String),
    #[error("rpc error: {0}")]
    RpcError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_node_entry_deserialize() {
        let json = r#"{
            "pubkey_ed25519": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "service_node_pubkey": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "funded": true,
            "active": true,
            "block_hash": "hash123"
        }"#;
        let entry: ServiceNodeEntry = serde_json::from_str(json).unwrap();
        assert!(entry.active);
        assert!(entry.funded);
        assert_eq!(entry.block_hash, "hash123");
    }

    #[test]
    fn test_get_service_nodes_response() {
        let json = r#"{
            "status": "OK",
            "service_node_states": [
                {
                    "pubkey_ed25519": "key1",
                    "service_node_pubkey": "sp1",
                    "funded": true,
                    "active": true,
                    "block_hash": "h1"
                }
            ],
            "block_hash": "latest_hash"
        }"#;
        let resp: GetServiceNodesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "OK");
        assert_eq!(resp.service_node_states.len(), 1);
        assert_eq!(resp.block_hash, Some("latest_hash".into()));
    }

    #[test]
    fn test_oxen_client_node_filtering() {
        let client = OxenRpcClient::new("http://localhost:22023/json_rpc".into());

        // Simulate receiving nodes
        let nodes = vec![
            ServiceNodeEntry {
                pubkey_ed25519: "k1".into(),
                service_node_pubkey: "s1".into(),
                funded: true,
                active: true,
                block_hash: "h".into(),
            },
            ServiceNodeEntry {
                pubkey_ed25519: "k2".into(),
                service_node_pubkey: "s2".into(),
                funded: false,
                active: true,
                block_hash: "h".into(),
            },
        ];

        *client.known_nodes.write() = nodes;
        assert_eq!(client.get_funded_active_nodes().len(), 1);
        assert_eq!(client.get_active_pubkeys().len(), 2);
    }
}
