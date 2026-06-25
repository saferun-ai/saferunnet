use std::path::PathBuf;

use saferunnet_core::{ModuleError, RuntimeModule, ServiceRegistry};
use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator};
use saferunnet_identity::{FileIdentityRepository, IdentitySpec};

pub const NODE_IDENTITY_SERVICE_KEY: &str = "saferunnet.identity.node";

pub struct IdentityModule {
    repository: FileIdentityRepository,
    spec: IdentitySpec,
    generator: Box<dyn KeyGenerator>,
}

impl IdentityModule {
    pub fn new(
        repository: FileIdentityRepository,
        spec: IdentitySpec,
        generator: Box<dyn KeyGenerator>,
    ) -> Self {
        Self {
            repository,
            spec,
            generator,
        }
    }

    pub fn from_runtime_settings(nickname: String, keyfile: PathBuf) -> Self {
        Self::new(
            FileIdentityRepository::new(keyfile),
            IdentitySpec {
                nickname,
                algorithm: KeyAlgorithm::Ed25519,
            },
            Box::new(Ed25519KeyGenerator::new()),
        )
    }
}

impl RuntimeModule for IdentityModule {
    fn name(&self) -> &'static str {
        "identity"
    }

    fn register_services(&mut self, services: &mut ServiceRegistry) -> Result<(), ModuleError> {
        let identity = self
            .repository
            .load_or_create(&self.spec, self.generator.as_ref())
            .map_err(|error| {
                ModuleError::Lifecycle(format!("failed to bootstrap node identity: {error}"))
            })?;
        services.insert_named(NODE_IDENTITY_SERVICE_KEY, identity);
        Ok(())
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }
}
