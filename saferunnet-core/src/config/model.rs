#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterConfig {
    pub nickname: String,
    pub data_dir: String,
    /// UDP bind port (default: 1090).
    pub bind_port: u16,
    /// RPC admin port (default: 1190).
    pub rpc_port: u16,
    /// Oxen daemon JSON-RPC endpoint for service node discovery.
    pub oxend_rpc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    pub bootstrap_routers: Vec<String>,
    pub exit: bool,
    pub reachable: bool,
    pub keyfile: Option<String>,
    pub ifaddr: Option<String>,
    pub exit_nodes: Vec<String>,
    pub hops: Option<u8>,
    pub paths: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedConfig {
    pub router: RouterConfig,
    pub logging: LoggingConfig,
    pub network: NetworkConfig,
    pub dns: DnsConfig,
}

/// DNS-specific configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    /// Upstream DNS resolver address (default: system resolver).
    pub upstream: Option<String>,
    /// Local DNS bind address.
    pub bind_addr: String,
    /// Whether to add a local DNS resolver on the TUN interface.
    pub add_resolvers: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstream: None,
            bind_addr: "127.3.2.1:53".into(),
            add_resolvers: true,
        }
    }
}

impl NormalizedConfig {
    /// Generate a minimal default configuration.
    pub fn default_config() -> Self {
        Self {
            router: RouterConfig {
                nickname: "saferunnet-node".into(),
                data_dir: "./var/lib/saferunnet".into(),
                bind_port: 1090,
                rpc_port: 1190,
                oxend_rpc: Some("http://127.0.0.1:22023/json_rpc".into()),
            },
            logging: LoggingConfig { level: "info".into() },
            network: NetworkConfig {
                bootstrap_routers: vec![],
                exit: false,
                reachable: false,
                keyfile: None,
                ifaddr: None,
                exit_nodes: vec![],
                hops: None,
                paths: None,
            },
            dns: DnsConfig::default(),
        }
    }
}

/// API / RPC configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind_addr: String,
    pub auth_token: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_addr: "127.0.0.1:1190".into(),
            auth_token: None,
        }
    }
}
