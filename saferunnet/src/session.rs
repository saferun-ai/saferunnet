use crate::link::{LinkMessageDispatcher, LinkSessionState};
use saferunnet_core::{ModuleError, RuntimeModule, ServiceKey, ServiceRegistry};
use tracing::info;

pub const SESSION_COORDINATOR_SERVICE_KEY: &str = "saferunnet.session.coordinator";

pub struct SessionCoordinatorModule {
    dispatcher: Option<LinkMessageDispatcher>,
    state: Option<LinkSessionState>,
    started: bool,
}

impl SessionCoordinatorModule {
    pub fn new() -> Self {
        Self {
            dispatcher: None,
            state: None,
            started: false,
        }
    }
}

impl Default for SessionCoordinatorModule {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeModule for SessionCoordinatorModule {
    fn name(&self) -> &'static str {
        "session-coordinator"
    }

    fn required_service_keys(&self) -> &[ServiceKey] {
        const KEYS: &[ServiceKey] = &[
            ServiceKey::of::<LinkMessageDispatcher>(
                crate::link::LINK_MESSAGE_DISPATCHER_SERVICE_KEY,
            ),
            ServiceKey::of::<LinkSessionState>(crate::link::LINK_SESSION_STATE_SERVICE_KEY),
        ];
        KEYS
    }

    fn wire(&mut self, services: &ServiceRegistry) -> Result<(), ModuleError> {
        let dispatcher = services
            .get_named::<LinkMessageDispatcher>(crate::link::LINK_MESSAGE_DISPATCHER_SERVICE_KEY)
            .ok_or_else(|| ModuleError::Wiring {
                module: "session-coordinator",
                reason: "missing link message dispatcher".into(),
            })?;
        self.dispatcher = Some(*dispatcher);

        let state = services
            .get_named::<LinkSessionState>(crate::link::LINK_SESSION_STATE_SERVICE_KEY)
            .ok_or_else(|| ModuleError::Wiring {
                module: "session-coordinator",
                reason: "missing link session state".into(),
            })?;
        self.state = Some(state.clone());

        Ok(())
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        self.started = true;
        info!("session coordinator started");
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        self.started = false;
        info!("session coordinator stopped");
        Ok(())
    }
}

impl SessionCoordinatorModule {
    pub fn dispatcher(&self) -> Option<&LinkMessageDispatcher> {
        self.dispatcher.as_ref()
    }

    pub fn session_state(&self) -> Option<&LinkSessionState> {
        self.state.as_ref()
    }

    pub fn is_started(&self) -> bool {
        self.started
    }
}
