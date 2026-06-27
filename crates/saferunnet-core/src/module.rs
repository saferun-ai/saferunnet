use thiserror::Error;

use crate::service::{ServiceKey, ServiceRegistry};

#[derive(Debug, Error)]
pub enum ModuleError {
    #[error("module lifecycle violation: {0}")]
    Lifecycle(String),
    #[error("module `{module}` service registration failed: {reason}")]
    ServiceRegistration {
        module: &'static str,
        reason: String,
    },
    #[error("module `{module}` wiring failed: {reason}")]
    Wiring {
        module: &'static str,
        reason: String,
    },
    #[error("module `{module}` startup failed: {reason}")]
    Startup {
        module: &'static str,
        reason: String,
    },
    #[error("module `{module}` shutdown failed: {reason}")]
    Shutdown {
        module: &'static str,
        reason: String,
    },
}

pub trait RuntimeModule {
    fn name(&self) -> &'static str;
    fn register_services(&mut self, _services: &mut ServiceRegistry) -> Result<(), ModuleError> {
        Ok(())
    }
    fn required_service_keys(&self) -> &[ServiceKey] {
        &[]
    }
    fn wire(&mut self, _services: &ServiceRegistry) -> Result<(), ModuleError> {
        Ok(())
    }
    fn start(&mut self) -> Result<(), ModuleError>;
    fn stop(&mut self) -> Result<(), ModuleError>;
}
