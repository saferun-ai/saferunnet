/// macOS NetworkExtension VPN provider integration.
/// For real VPN integration on macOS, a NetworkExtension bundle is needed.
#[cfg(target_os = "macos")]
pub mod apple_ne {
    /// Bundle identifier for the NetworkExtension provider.
    pub const BUNDLE_ID: &str = "net.saferunnet.vpn";
    /// Provider bundle display name.
    pub const DISPLAY_NAME: &str = "SaferunNet VPN";

    /// Check if running as a NetworkExtension provider.
    pub fn is_ne_provider() -> bool {
        // NetworkExtension providers are launched with specific env vars
        std::env::var("NETWORK_EXTENSION").is_ok()
    }

    /// Start the VPN tunnel from the NE context.
    pub fn start_tunnel(config: &str) -> Result<(), String> {
        tracing::info!("NE provider: starting tunnel with config: {config}");
        Ok(())
    }

    /// Stop the VPN tunnel.
    pub fn stop_tunnel() {
        tracing::info!("NE provider: stopping tunnel");
    }
}

/// Stub for non-macOS.
#[cfg(not(target_os = "macos"))]
pub mod apple_ne {
    pub fn is_ne_provider() -> bool { false }
    pub fn start_tunnel(_: &str) -> Result<(), String> { Err("not on macOS".into()) }
    pub fn stop_tunnel() {}
}
