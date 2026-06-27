#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterConfig {
    pub nickname: String,
    pub data_dir: String,
    /// UDP bind port (default: 1090).
    pub bind_port: u16,
    /// RPC admin port (default: 1190).
    pub rpc_port: u16,
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
}
