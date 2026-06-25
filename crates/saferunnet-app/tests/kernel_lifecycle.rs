use saferunnet_app::AppKernel;
use saferunnet_core::{LifecycleState, ModuleError, RuntimeModule};
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
