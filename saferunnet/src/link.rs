use std::sync::{Arc, Mutex};

use saferunnet_core::{AuthenticatedLinkMessage, LinkMessageError, SessionState};
use saferunnet_core::{ModuleError, RuntimeModule, ServiceKey, ServiceRegistry};

pub const LINK_MESSAGE_DISPATCHER_SERVICE_KEY: &str = "saferunnet.link.dispatcher";
pub const LINK_SESSION_STATE_SERVICE_KEY: &str = "saferunnet.link.session-state";

pub type LinkSessionState = Arc<Mutex<SessionState>>;

#[derive(Debug, Default, Clone, Copy)]
pub struct LinkMessageDispatcher;

impl LinkMessageDispatcher {
    pub fn new() -> Self {
        Self
    }

    pub fn decode_verified(
        &self,
        input: &[u8],
    ) -> Result<AuthenticatedLinkMessage, LinkMessageError> {
        AuthenticatedLinkMessage::decode_verified(input)
    }

    pub fn decode_unverified(
        &self,
        input: &[u8],
    ) -> Result<AuthenticatedLinkMessage, LinkMessageError> {
        AuthenticatedLinkMessage::decode_unverified(input)
    }

    pub fn decode(&self, input: &[u8]) -> Result<AuthenticatedLinkMessage, LinkMessageError> {
        AuthenticatedLinkMessage::decode(input)
    }
}

#[derive(Debug, Default)]
pub struct LinkMessageModule;

impl LinkMessageModule {
    pub fn new() -> Self {
        Self
    }
}

impl RuntimeModule for LinkMessageModule {
    fn name(&self) -> &'static str {
        "link-message-dispatcher"
    }

    fn register_services(&mut self, services: &mut ServiceRegistry) -> Result<(), ModuleError> {
        services.insert_named(
            LINK_MESSAGE_DISPATCHER_SERVICE_KEY,
            LinkMessageDispatcher::new(),
        );
        Ok(())
    }

    fn required_service_keys(&self) -> &[ServiceKey] {
        const KEYS: &[ServiceKey] = &[ServiceKey::of::<LinkMessageDispatcher>(
            LINK_MESSAGE_DISPATCHER_SERVICE_KEY,
        )];
        KEYS
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LinkSessionStateModule {
    state: LinkSessionState,
}

impl Default for LinkSessionStateModule {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkSessionStateModule {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(SessionState::new())),
        }
    }

    pub fn from_shared_state(state: LinkSessionState) -> Self {
        Self { state }
    }
}

impl RuntimeModule for LinkSessionStateModule {
    fn name(&self) -> &'static str {
        "link-session-state"
    }

    fn register_services(&mut self, services: &mut ServiceRegistry) -> Result<(), ModuleError> {
        services.insert_named(LINK_SESSION_STATE_SERVICE_KEY, self.state.clone());
        Ok(())
    }

    fn required_service_keys(&self) -> &[ServiceKey] {
        const KEYS: &[ServiceKey] = &[ServiceKey::of::<LinkSessionState>(
            LINK_SESSION_STATE_SERVICE_KEY,
        )];
        KEYS
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }
}
