use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// RPC command: initiate a session to a remote node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInitCmd {
    pub remote_pubkey: String,
    pub exit: Option<bool>,
    pub tun: Option<bool>,
}

/// RPC command: close a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCloseCmd {
    pub session_id: u64,
}

/// RPC command: lookup a service node via DHT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupSnodeCmd {
    pub pubkey: String,
}

/// RPC command: find a client contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindCCCmd {
    pub client_id: String,
}

/// RPC command: connect to a remote via QUIC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConnectCmd {
    pub remote_addr: String,
}

/// RPC command: start a QUIC listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicListenerCmd {
    pub bind_addr: String,
}

/// RPC command: map an exit node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapExitCmd {
    pub exit_pubkey: String,
    pub ip_range: Option<String>,
}

/// RPC command: list all exit mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListExitsCmd;

/// RPC command: unmap an exit node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnmapExitCmd {
    pub exit_pubkey: String,
}

/// RPC command: swap exit nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapExitsCmd {
    pub old_pubkey: String,
    pub new_pubkey: String,
}

/// RPC command: runtime config update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigCmd {
    pub key: String,
    pub value: JsonValue,
}

/// RPC command: get node status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusCmd;

/// RPC command: halt (remote shutdown).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaltCmd;

/// RPC command: version info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionCmd;
