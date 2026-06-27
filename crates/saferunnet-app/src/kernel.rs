use saferunnet_core::{LifecycleState, ModuleError, RuntimeHandle, RuntimeModule, ServiceRegistry};
use std::sync::Arc;

pub struct AppKernel {
    state: LifecycleState,
    modules: Vec<Box<dyn RuntimeModule>>,
    services: ServiceRegistry,
    runtime: RuntimeHandle,
}

impl AppKernel {
    pub fn new() -> Self {
        Self {
            state: LifecycleState::Created,
            modules: Vec::new(),
            services: ServiceRegistry::new(),
            runtime: Arc::new(tokio::runtime::Runtime::new().expect("create tokio runtime")),
        }
    }

    pub fn from_runtime(runtime: RuntimeHandle) -> Self {
        Self {
            state: LifecycleState::Created,
            modules: Vec::new(),
            services: ServiceRegistry::new(),
            runtime,
        }
    }

    pub fn runtime(&self) -> &RuntimeHandle {
        &self.runtime
    }

    pub fn register(&mut self, module: Box<dyn RuntimeModule>) {
        self.modules.push(module);
    }

    pub fn state(&self) -> LifecycleState {
        self.state
    }

    pub fn services(&self) -> &ServiceRegistry {
        &self.services
    }

    pub fn services_mut(&mut self) -> &mut ServiceRegistry {
        &mut self.services
    }

    pub fn start(&mut self) -> Result<(), ModuleError> {
        if self.state != LifecycleState::Created && self.state != LifecycleState::Stopped {
            return Err(ModuleError::Lifecycle(format!(
                "cannot start from {:?}",
                self.state
            )));
        }

        self.state = LifecycleState::Starting;

        // Phase 1: register services with rollback
        let count = self.modules.len();
        for i in 0..count {
            if let Err(err) = self.modules[i].register_services(&mut self.services) {
                // Rollback: stop previously registered modules
                for j in (0..i).rev() {
                    if let Err(stop_err) = self.modules[j].stop() {
                        tracing::warn!(
                            "rollback stop failed for module {}: {stop_err}",
                            self.modules[j].name()
                        );
                    }
                }
                self.services.clear_registrations();
                self.state = LifecycleState::Stopped;
                let name = self.modules[i].name();
                return Err(ModuleError::ServiceRegistration {
                    module: name,
                    reason: err.to_string(),
                });
            }
        }

        // Phase 2: check deps, wire, start
        for i in 0..count {
            // Check required services
            let required_keys: Vec<_> = self.modules[i].required_service_keys().to_vec();
            for required in &required_keys {
                if !self.services.contains_key_typed(required) {
                    self.rollback_started(i)?;
                    self.state = LifecycleState::Stopped;
                    let name = self.modules[i].name();
                    return Err(ModuleError::Lifecycle(format!(
                        "module {} requires missing service {}",
                        name,
                        required.name()
                    )));
                }
            }
            // Wire
            if let Err(err) = self.modules[i].wire(&self.services) {
                self.rollback_started(i)?;
                self.state = LifecycleState::Stopped;
                let name = self.modules[i].name();
                return Err(ModuleError::Wiring {
                    module: name,
                    reason: err.to_string(),
                });
            }
            // Start
            if let Err(err) = self.modules[i].start() {
                self.rollback_started(i)?;
                self.state = LifecycleState::Stopped;
                let name = self.modules[i].name();
                return Err(ModuleError::Startup {
                    module: name,
                    reason: err.to_string(),
                });
            }
        }
        self.state = LifecycleState::Running;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), ModuleError> {
        if self.state != LifecycleState::Running {
            return Err(ModuleError::Lifecycle(format!(
                "cannot stop from {:?}",
                self.state
            )));
        }

        self.state = LifecycleState::Stopping;
        let count = self.modules.len();
        for i in (0..count).rev() {
            if let Err(err) = self.modules[i].stop() {
                self.state = LifecycleState::Stopped;
                let name = self.modules[i].name();
                return Err(ModuleError::Shutdown {
                    module: name,
                    reason: err.to_string(),
                });
            }
        }
        self.state = LifecycleState::Stopped;
        Ok(())
    }

    fn rollback_started(&mut self, count: usize) -> Result<(), ModuleError> {
        for i in (0..count).rev() {
            self.modules[i].stop()?;
        }
        Ok(())
    }
}

impl Default for AppKernel {
    fn default() -> Self {
        Self::new()
    }
}
