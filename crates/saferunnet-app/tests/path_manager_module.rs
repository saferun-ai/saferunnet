use saferunnet_app::{AppKernel, PATH_SELECTOR_SERVICE_KEY, PathManagerModule, SharedPathSelector};
use saferunnet_core::{RuntimeModule, ServiceKey};

#[test]
fn kernel_publishes_path_services_on_startup() {
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(PathManagerModule::new()));
    kernel.start().expect("kernel should start");
    assert!(
        kernel
            .services()
            .contains_key_typed(&ServiceKey::of::<SharedPathSelector>(
                PATH_SELECTOR_SERVICE_KEY,
            ))
    );
}

#[test]
fn path_services_are_available_in_dependent_module() {
    struct PathConsumer {
        started: bool,
    }

    impl RuntimeModule for PathConsumer {
        fn name(&self) -> &'static str {
            "path-consumer"
        }
        fn required_service_keys(&self) -> &[ServiceKey] {
            const KEYS: &[ServiceKey] = &[ServiceKey::of::<SharedPathSelector>(
                PATH_SELECTOR_SERVICE_KEY,
            )];
            KEYS
        }
        fn start(&mut self) -> Result<(), saferunnet_core::ModuleError> {
            self.started = true;
            Ok(())
        }
        fn stop(&mut self) -> Result<(), saferunnet_core::ModuleError> {
            Ok(())
        }
    }

    let mut kernel = AppKernel::new();
    kernel.register(Box::new(PathManagerModule::new()));
    let consumer = PathConsumer { started: false };
    kernel.register(Box::new(consumer));
    kernel.start().expect("kernel should start");
    assert!(kernel.state() == saferunnet_core::LifecycleState::Running);
}

#[test]
fn path_services_missing_rejected_without_provider() {
    struct PathConsumer;
    impl RuntimeModule for PathConsumer {
        fn name(&self) -> &'static str {
            "path-consumer"
        }
        fn required_service_keys(&self) -> &[ServiceKey] {
            const KEYS: &[ServiceKey] = &[ServiceKey::of::<SharedPathSelector>(
                PATH_SELECTOR_SERVICE_KEY,
            )];
            KEYS
        }
        fn start(&mut self) -> Result<(), saferunnet_core::ModuleError> {
            Ok(())
        }
        fn stop(&mut self) -> Result<(), saferunnet_core::ModuleError> {
            Ok(())
        }
    }

    let mut kernel = AppKernel::new();
    kernel.register(Box::new(PathConsumer));
    let err = kernel
        .start()
        .expect_err("should fail without path manager");
    assert!(matches!(err, saferunnet_core::ModuleError::Lifecycle(_)));
}

#[test]
fn path_manager_stops_cleanly() {
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(PathManagerModule::new()));
    kernel.start().expect("kernel should start");
    kernel.stop().expect("kernel should stop");
    assert!(kernel.state() == saferunnet_core::LifecycleState::Stopped);
}
