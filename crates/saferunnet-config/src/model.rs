#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterConfig {
    pub nickname: String,
    pub data_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    pub exit: bool,
    pub reachable: bool,
    pub keyfile: Option<String>,
    pub ifaddr: Option<String>,
    pub exit_nodes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedConfig {
    pub router: RouterConfig,
    pub logging: LoggingConfig,
    pub network: NetworkConfig,
}
