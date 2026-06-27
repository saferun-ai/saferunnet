use std::sync::{Arc, Mutex};

use saferunnet_core::{ModuleError, RuntimeModule, ServiceKey, ServiceRegistry};
use saferunnet_crypto::PublicKey;
use saferunnet_core::path::{
    build::RandomPathBuilder, health::PingHealthChecker, select::FirstAvailableSelector,
};

pub const PATH_SELECTOR_SERVICE_KEY: &str = "saferunnet.path.selector";
pub const PATH_BUILDER_SERVICE_KEY: &str = "saferunnet.path.builder";
pub const PATH_HEALTH_SERVICE_KEY: &str = "saferunnet.path.health";

use saferunnet_core::path::{build::PathBuilder, health::PathHealthChecker, select::PathSelector};

pub type SharedPathSelector = Arc<Mutex<dyn PathSelector + Send>>;
pub type SharedPathBuilder = Arc<Mutex<dyn PathBuilder + Send>>;
pub type SharedPathHealthChecker = Arc<Mutex<dyn PathHealthChecker + Send>>;

#[derive(Debug)]
pub struct PathManagerModule {
    registered: bool,
    router_pool: Vec<PublicKey>,
}

impl PathManagerModule {
    pub fn new() -> Self {
        Self {
            registered: false,
            router_pool: Vec::new(),
        }
    }

    pub fn with_router_pool(router_pool: Vec<PublicKey>) -> Self {
        Self {
            registered: false,
            router_pool,
        }
    }
}

impl Default for PathManagerModule {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeModule for PathManagerModule {
    fn name(&self) -> &'static str {
        "path-manager"
    }

    fn register_services(&mut self, services: &mut ServiceRegistry) -> Result<(), ModuleError> {
        let selector: SharedPathSelector = Arc::new(Mutex::new(FirstAvailableSelector::new()));
        let builder: SharedPathBuilder =
            Arc::new(Mutex::new(RandomPathBuilder::new(self.router_pool.clone())));
        let health: SharedPathHealthChecker = Arc::new(Mutex::new(PingHealthChecker::new()));

        services.register_with_key(
            ServiceKey::of::<SharedPathSelector>(PATH_SELECTOR_SERVICE_KEY),
            Box::new(selector),
        );
        services.register_with_key(
            ServiceKey::of::<SharedPathBuilder>(PATH_BUILDER_SERVICE_KEY),
            Box::new(builder),
        );
        services.register_with_key(
            ServiceKey::of::<SharedPathHealthChecker>(PATH_HEALTH_SERVICE_KEY),
            Box::new(health),
        );
        self.registered = true;
        Ok(())
    }

    fn required_service_keys(&self) -> &[ServiceKey] {
        &[]
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        self.registered = false;
        Ok(())
    }
}
