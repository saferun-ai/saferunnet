use saferunnet_core::{ModuleError, RuntimeModule, ServiceRegistry};
use saferunnet_link::{AuthenticatedLinkMessage, LinkMessageError};

pub const LINK_MESSAGE_DISPATCHER_SERVICE_KEY: &str = "saferunnet.link.dispatcher";

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

    fn start(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }
}
