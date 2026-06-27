use std::sync::{Arc, Mutex};

use saferunnet_core::{ModuleError, RuntimeModule, ServiceKey, ServiceRegistry};
use saferunnet_crypto::PublicKey;
use saferunnet_dns::resolver::{DnsError, LokiResolver};

pub const DNS_RESOLVER_SERVICE_KEY: &str = "saferunnet.dns.resolver";

pub type SharedLokiResolver = Arc<Mutex<dyn LokiResolver + Send>>;

pub struct DnsResolverModule {
    resolver: Option<SharedLokiResolver>,
}

impl DnsResolverModule {
    pub fn new() -> Self {
        Self { resolver: None }
    }

    /// Provide a custom resolver (e.g. DHT-backed).
    /// If not set, a stub resolver is used by default.
    pub fn with_resolver<R: LokiResolver + Send + 'static>(mut self, resolver: R) -> Self {
        self.resolver = Some(Arc::new(Mutex::new(resolver)));
        self
    }
}

impl Default for DnsResolverModule {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeModule for DnsResolverModule {
    fn name(&self) -> &'static str {
        "dns-resolver"
    }

    fn register_services(&mut self, services: &mut ServiceRegistry) -> Result<(), ModuleError> {
        let resolver: SharedLokiResolver = self
            .resolver
            .take()
            .unwrap_or_else(|| Arc::new(Mutex::new(StubLokiResolver)));
        services.register_with_key(
            ServiceKey::of::<SharedLokiResolver>(DNS_RESOLVER_SERVICE_KEY),
            Box::new(resolver),
        );
        Ok(())
    }

    fn required_service_keys(&self) -> &[ServiceKey] {
        &[]
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }
}

/// Stub resolver that returns empty results — placeholder until DHT-backed resolver is built.
struct StubLokiResolver;

impl LokiResolver for StubLokiResolver {
    fn resolve(&self, name: &str) -> Result<Vec<PublicKey>, DnsError> {
        if !saferunnet_dns::resolver::is_loki_name(name) {
            return Err(DnsError::NotLokiName(name.to_string()));
        }
        Ok(Vec::new())
    }
}
