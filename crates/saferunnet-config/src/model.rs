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
pub struct NormalizedConfig {
    pub router: RouterConfig,
    pub logging: LoggingConfig,
}
