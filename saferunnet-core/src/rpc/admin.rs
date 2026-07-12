use serde::{Deserialize, Serialize};

/// Status snapshot of the local node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node_id: String,
    pub uptime_secs: u64,
    pub connected_routers: usize,
    pub connected_clients: usize,
    pub active_paths: usize,
    pub version: String,
}

impl Default for NodeStatus {
    fn default() -> Self {
        Self {
            node_id: "unknown".into(),
            uptime_secs: 0,
            connected_routers: 0,
            connected_clients: 0,
            active_paths: 0,
            version: "0.2.0".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerInfo {
    pub router_id: String,
    pub addresses: Vec<String>,
    pub connected: bool,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStats {
    pub total_peers: usize,
    pub bucket_counts: Vec<usize>,
}

/// Trait for the admin handler — injected into the RPC server.
pub trait AdminHandler: Send + Sync {
    fn status(&self) -> NodeStatus { NodeStatus::default() }
    fn list_peers(&self) -> Vec<PeerInfo> { vec![] }
    fn dht_stats(&self) -> DhtStats { DhtStats { total_peers: 0, bucket_counts: vec![] } }
    fn stop(&self) -> bool { false }

    fn session_init(&self, _remote_pubkey: &str, _exit: bool, _tun: bool) -> serde_json::Value {
        serde_json::json!({"ok": false, "error": "not implemented"})
    }
    fn session_close(&self, _session_id: u64) -> serde_json::Value {
        serde_json::json!({"ok": false, "error": "not implemented"})
    }
    fn lookup_snode(&self, _pubkey: &str) -> serde_json::Value {
        serde_json::json!({"error": "not found"})
    }
    fn map_exit(&self, _exit_pubkey: &str, _ip_range: Option<&str>) -> serde_json::Value {
        serde_json::json!({"ok": false})
    }
    fn list_exits(&self) -> serde_json::Value {
        serde_json::json!({"exits": []})
    }
    fn unmap_exit(&self, _exit_pubkey: &str) -> serde_json::Value {
        serde_json::json!({"ok": true})
    }
    fn swap_exits(&self, _old: &str, _new: &str) -> serde_json::Value {
        serde_json::json!({"ok": false})
    }
    fn update_config(&self, _key: &str, _value: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({"ok": false, "error": "not supported"})
    }
    fn halt(&self) -> serde_json::Value { serde_json::json!({"ok": false}) }
    fn version(&self) -> serde_json::Value { serde_json::json!({"version": "0.2.0", "protocol": 1}) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn test_node_status_defaults() { let s = NodeStatus::default(); assert_eq!(s.node_id, "unknown"); assert_eq!(s.uptime_secs, 0); assert_eq!(s.version, "0.2.0"); }
    #[test] fn test_node_status_serialize() { let s = NodeStatus { node_id: "test".into(), uptime_secs: 3600, connected_routers: 5, connected_clients: 10, active_paths: 3, version: "0.3.0".into() }; let json = serde_json::to_string(&s).unwrap(); let d: NodeStatus = serde_json::from_str(&json).unwrap(); assert_eq!(d.node_id, "test"); }
    #[test] fn test_peer_info() { let p = PeerInfo { router_id: "ab".repeat(32), addresses: vec!["10.0.0.1:1090".into()], connected: true, last_seen: 1700000000 }; let json = serde_json::to_string(&p).unwrap(); let d: PeerInfo = serde_json::from_str(&json).unwrap(); assert_eq!(d, p); }
    #[test] fn test_dht_stats() { let s = DhtStats { total_peers: 42, bucket_counts: vec![8, 16, 10, 8] }; let json = serde_json::to_string(&s).unwrap(); let d: DhtStats = serde_json::from_str(&json).unwrap(); assert_eq!(d.total_peers, 42); }
    #[test] fn test_admin_handler_defaults() { struct Dh; impl AdminHandler for Dh {} let h = Dh; assert_eq!(h.status().node_id, "unknown"); assert!(h.list_peers().is_empty()); assert!(!h.stop()); assert_eq!(h.version()["version"], "0.2.0"); }
}
