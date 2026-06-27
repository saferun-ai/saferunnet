use saferunnet_app::{AppKernel, DNS_RESOLVER_SERVICE_KEY, DnsResolverModule, SharedLokiResolver};
use saferunnet_core::{RuntimeModule, ServiceKey};

#[test]
fn kernel_publishes_dns_service_on_startup() {
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(DnsResolverModule::new()));
    kernel.start().expect("kernel should start");
    assert!(
        kernel
            .services()
            .contains_key_typed(&ServiceKey::of::<SharedLokiResolver>(
                DNS_RESOLVER_SERVICE_KEY,
            ))
    );
}

#[test]
fn dns_service_available_in_dependent_module() {
    struct DnsConsumer {
        started: bool,
    }
    impl RuntimeModule for DnsConsumer {
        fn name(&self) -> &'static str {
            "dns-consumer"
        }
        fn required_service_keys(&self) -> &[ServiceKey] {
            const KEYS: &[ServiceKey] = &[ServiceKey::of::<SharedLokiResolver>(
                DNS_RESOLVER_SERVICE_KEY,
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
    kernel.register(Box::new(DnsResolverModule::new()));
    kernel.register(Box::new(DnsConsumer { started: false }));
    kernel.start().expect("kernel should start");
}

#[test]
fn dns_missing_resolver_rejected_without_provider() {
    struct DnsConsumer;
    impl RuntimeModule for DnsConsumer {
        fn name(&self) -> &'static str {
            "dns-consumer"
        }
        fn required_service_keys(&self) -> &[ServiceKey] {
            const KEYS: &[ServiceKey] = &[ServiceKey::of::<SharedLokiResolver>(
                DNS_RESOLVER_SERVICE_KEY,
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
    kernel.register(Box::new(DnsConsumer));
    let err = kernel
        .start()
        .expect_err("should fail without dns resolver");
    assert!(matches!(err, saferunnet_core::ModuleError::Lifecycle(_)));
}
