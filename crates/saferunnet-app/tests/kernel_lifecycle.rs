use saferunnet_app::AppKernel;
use saferunnet_core::{LifecycleState, ModuleError, RuntimeModule, ServiceRegistry};
use std::sync::{Arc, Mutex};

struct RecordingModule {
    name: &'static str,
    events: Arc<Mutex<Vec<String>>>,
}

impl RuntimeModule for RecordingModule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("start:{}", self.name));
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("stop:{}", self.name));
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct SharedNickname(&'static str);

struct WiringModule {
    captured: Option<String>,
}

impl RuntimeModule for WiringModule {
    fn name(&self) -> &'static str {
        "wiring"
    }

    fn wire(&mut self, services: &ServiceRegistry) -> Result<(), ModuleError> {
        let nickname = services
            .get::<SharedNickname>()
            .ok_or_else(|| ModuleError::Lifecycle("missing SharedNickname".to_string()))?;
        self.captured = Some(nickname.0.to_string());
        Ok(())
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        let captured = self
            .captured
            .as_deref()
            .ok_or_else(|| ModuleError::Lifecycle("module started before wiring".to_string()))?;
        assert_eq!(captured, "edge-service");
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }
}

#[test]
fn kernel_starts_and_stops_modules_in_order() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(RecordingModule {
        name: "config",
        events: events.clone(),
    }));
    kernel.register(Box::new(RecordingModule {
        name: "router",
        events: events.clone(),
    }));

    assert_eq!(kernel.state(), LifecycleState::Created);
    kernel.start().unwrap();
    kernel.stop().unwrap();

    assert_eq!(
        events.lock().unwrap().as_slice(),
        ["start:config", "start:router", "stop:router", "stop:config"]
    );
    assert_eq!(kernel.state(), LifecycleState::Stopped);
}

#[test]
fn kernel_rejects_double_start() {
    let mut kernel = AppKernel::new();
    kernel.start().unwrap();
    let error = kernel.start().unwrap_err();
    assert!(error.to_string().contains("cannot start"));
}

#[test]
fn kernel_wires_registered_services_before_start() {
    let mut kernel = AppKernel::new();
    kernel.services_mut().insert(SharedNickname("edge-service"));
    kernel.register(Box::new(WiringModule { captured: None }));

    kernel.start().unwrap();

    assert_eq!(kernel.state(), LifecycleState::Running);
}

struct FailingModule {
    name: &'static str,
    events: Arc<Mutex<Vec<String>>>,
}

impl RuntimeModule for FailingModule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("start:{}", self.name));
        Err(ModuleError::Lifecycle("boom".to_string()))
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("stop:{}", self.name));
        Ok(())
    }
}

#[test]
fn kernel_rolls_back_started_modules_when_a_later_module_fails() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(RecordingModule {
        name: "config",
        events: events.clone(),
    }));
    kernel.register(Box::new(FailingModule {
        name: "router",
        events: events.clone(),
    }));

    let error = kernel.start().unwrap_err();

    assert!(error.to_string().contains("boom"));
    assert_eq!(
        events.lock().unwrap().as_slice(),
        ["start:config", "start:router", "stop:config"]
    );
    assert_eq!(kernel.state(), LifecycleState::Stopped);
}
