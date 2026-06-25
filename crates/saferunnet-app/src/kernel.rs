use saferunnet_core::{LifecycleState, ModuleError, RuntimeModule, ServiceRegistry};

pub struct AppKernel {
    state: LifecycleState,
    modules: Vec<Box<dyn RuntimeModule>>,
    services: ServiceRegistry,
}

impl AppKernel {
    pub fn new() -> Self {
        Self {
            state: LifecycleState::Created,
            modules: Vec::new(),
            services: ServiceRegistry::new(),
        }
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
        for module in &mut self.modules {
            module.register_services(&mut self.services)?;
        }
        for (started, module) in self.modules.iter_mut().enumerate() {
            for required in module.required_service_keys() {
                if !self.services.contains_key(required) {
                    self.state = LifecycleState::Stopped;
                    return Err(ModuleError::Lifecycle(format!(
                        "module {} requires missing service {}",
                        module.name(),
                        required
                    )));
                }
            }
            module.wire(&self.services)?;
            if let Err(error) = module.start() {
                self.rollback_started_modules(started)?;
                self.state = LifecycleState::Stopped;
                return Err(error);
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
        for module in self.modules.iter_mut().rev() {
            module.stop()?;
        }
        self.state = LifecycleState::Stopped;
        Ok(())
    }

    fn rollback_started_modules(&mut self, started: usize) -> Result<(), ModuleError> {
        for module in self.modules[..started].iter_mut().rev() {
            module.stop()?;
        }
        Ok(())
    }
}

impl Default for AppKernel {
    fn default() -> Self {
        Self::new()
    }
}
