use std::sync::Arc;

use saferunnet_core::bootstrap::BootstrapList;
use saferunnet_core::nodedb::NodeDB;
use saferunnet_core::oxen_bridge::OxenBootstrapper;
use saferunnet_core::{ModuleError, RuntimeModule, ServiceKey, ServiceRegistry};

pub const OXEN_BOOTSTRAPPER_SERVICE_KEY: &str = "saferunnet.oxen.bootstrapper";
pub const NODE_DB_SERVICE_KEY: &str = "saferunnet.nodedb";
pub const BOOTSTRAP_LIST_SERVICE_KEY: &str = "saferunnet.bootstrap";

pub type SharedNodeDB = Arc<NodeDB>;
pub type SharedBootstrapList = Arc<parking_lot::RwLock<BootstrapList>>;

/// Module that wires the Oxen chain bootstrapper into the daemon lifecycle.
///
/// On startup: fetches service nodes from oxend → builds RouterContacts → populates NodeDB.
/// On run: spawns a background periodic refresh task.
pub struct OxenBootstrapModule {
    oxend_url: String,
    db: Option<SharedNodeDB>,
    bootstrap: Option<SharedBootstrapList>,
    bootstrapper: Option<Arc<OxenBootstrapper>>,
}

impl OxenBootstrapModule {
    pub fn new(oxend_url: String) -> Self {
        Self {
            oxend_url,
            db: None,
            bootstrap: None,
            bootstrapper: None,
        }
    }
}

impl RuntimeModule for OxenBootstrapModule {
    fn name(&self) -> &'static str {
        "oxen-bootstrap"
    }

    fn required_service_keys(&self) -> &[ServiceKey] {
        &[]
    }

    fn register_services(&mut self, services: &mut ServiceRegistry) -> Result<(), ModuleError> {
        // Create shared state
        let bootstrap = Arc::new(parking_lot::RwLock::new(BootstrapList::new()));
        let node_db = Arc::new(NodeDB::new(BootstrapList::new()));

        let bootstrapper = OxenBootstrapper::new(
            self.oxend_url.clone(),
            node_db.clone(),
            bootstrap.clone(),
        );

        self.db = Some(node_db.clone());
        self.bootstrap = Some(bootstrap.clone());
        self.bootstrapper = Some(Arc::new(bootstrapper));

        // Register into service registry for other modules to use
        services.insert_named(NODE_DB_SERVICE_KEY, node_db);
        services.insert_named(BOOTSTRAP_LIST_SERVICE_KEY, bootstrap);

        Ok(())
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        let bootstrapper = self.bootstrapper.clone().ok_or_else(|| {
            ModuleError::Lifecycle("oxen bootstrapper not initialised".into())
        })?;

        let handle = tokio::runtime::Handle::current();

        // Do initial fetch
        handle.block_on(async {
            match bootstrapper.fetch_and_populate().await {
                Ok(n) => tracing::info!("oxen bootstrap: {} nodes loaded from chain", n),
                Err(e) => tracing::warn!("oxen bootstrap: initial fetch failed (will retry): {e}"),
            }
        });

        // Spawn periodic refresh
        let bootstrapper_clone = bootstrapper.clone();
        handle.spawn(async move {
            bootstrapper_clone
                .run_periodic(saferunnet_core::oxen_bridge::DEFAULT_REFRESH_INTERVAL)
                .await;
        });

        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        tracing::info!("oxen bootstrap module stopped");
        Ok(())
    }
}
