use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BootstrapPhase {
    Init,
    IdentityLoad,
    NodedbInit,
    LinkBind,
    BootstrapFetch,
    DhtJoin,
    PathBuild,
    Running,
}

#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub listen_addr: SocketAddr,
    pub min_rcs_for_bootstrap: usize,
    pub max_paths: usize,
    pub path_build_delay_ms: u64,
    pub min_hops: usize,
    pub max_hops: usize,
    pub path_lifetime_secs: u64,
    pub path_build_timeout_secs: u64,
    pub allow_transit: bool,
    pub is_exit: bool,
    pub tun_ifname: Option<String>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:22000".parse().unwrap(),
            min_rcs_for_bootstrap: 6,
            max_paths: 8,
            path_build_delay_ms: 5000,
            min_hops: 2,
            max_hops: 5,
            path_lifetime_secs: 600,
            path_build_timeout_secs: 10,
            allow_transit: true,
            is_exit: false,
            tun_ifname: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RouterState {
    pub num_paths_active: usize,
    pub num_paths_building: usize,
    pub num_rcs_known: usize,
    pub num_link_sessions: usize,
    pub num_client_sessions: usize,
    pub uptime_secs: u64,
    pub transit_bytes: u64,
    pub session_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let c = RouterConfig::default();
        assert_eq!(c.min_rcs_for_bootstrap, 6);
        assert_eq!(c.max_paths, 8);
    }
}
