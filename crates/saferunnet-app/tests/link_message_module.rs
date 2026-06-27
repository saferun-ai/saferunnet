use saferunnet_app::{
    AppKernel, LINK_MESSAGE_DISPATCHER_SERVICE_KEY, LinkMessageDispatcher, LinkMessageModule,
};
use saferunnet_core::{ModuleError, RuntimeModule, ServiceKey, ServiceRegistry};
use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator};
use saferunnet_identity::NodeIdentity;
use saferunnet_service::{
    AuthenticatedLinkMessage, AuthenticatedPathControlMessage, AuthenticatedSessionAcceptMessage,
    AuthenticatedSessionInitMessage, AuthenticatedSessionPathSwitchMessage, PathControlMessage,
    PathPing, SessionAcceptMessage, SessionHopId, SessionInitMessage, SessionPathSwitchMessage,
    SessionTag,
};

fn make_identity(nickname: &str) -> NodeIdentity {
    let key_pair = Ed25519KeyGenerator::new()
        .generate(KeyAlgorithm::Ed25519)
        .expect("test key generation should succeed");
    NodeIdentity {
        nickname: nickname.to_string(),
        algorithm: KeyAlgorithm::Ed25519,
        secret_key: key_pair.secret_key,
        public_key: key_pair.public_key,
    }
}

fn hop(seed: u8) -> SessionHopId {
    SessionHopId::new([seed; 16])
}

fn encoded_path_control(identity: &NodeIdentity) -> Vec<u8> {
    AuthenticatedPathControlMessage::sign(
        identity,
        PathControlMessage::Ping(PathPing { request_id: 42 }),
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed")
}

fn encoded_session_init(identity: &NodeIdentity) -> Vec<u8> {
    AuthenticatedSessionInitMessage::sign(
        identity,
        SessionInitMessage {
            initiator: identity.public_key.clone(),
            local_pivot: hop(0x11),
            remote_pivot: hop(0x22),
            auth_token: Some(vec![0xaa, 0xbb]),
        },
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed")
}

fn encoded_session_path_switch(identity: &NodeIdentity) -> Vec<u8> {
    AuthenticatedSessionPathSwitchMessage::sign(
        identity,
        SessionPathSwitchMessage {
            local_pivot: hop(0x33),
            remote_pivot: hop(0x44),
            session_tag: SessionTag::new(77),
        },
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed")
}

fn encoded_session_accept(identity: &NodeIdentity) -> Vec<u8> {
    AuthenticatedSessionAcceptMessage::sign(
        identity,
        SessionAcceptMessage {
            session_tag: SessionTag::new(77),
        },
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed")
}

struct DispatcherWiringProbe {
    wired: bool,
}

impl RuntimeModule for DispatcherWiringProbe {
    fn name(&self) -> &'static str {
        "dispatcher-wiring-probe"
    }

    fn required_service_keys(&self) -> &[ServiceKey] {
        const KEYS: &[ServiceKey] = &[ServiceKey::of::<LinkMessageDispatcher>(
            LINK_MESSAGE_DISPATCHER_SERVICE_KEY,
        )];
        KEYS
    }

    fn wire(&mut self, services: &ServiceRegistry) -> Result<(), ModuleError> {
        let _dispatcher = services
            .get::<LinkMessageDispatcher>()
            .ok_or_else(|| ModuleError::Lifecycle("missing LinkMessageDispatcher".to_string()))?;
        self.wired = true;
        Ok(())
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        if !self.wired {
            return Err(ModuleError::Lifecycle(
                "dispatcher was not available during wiring".to_string(),
            ));
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }
}

#[test]
fn kernel_publishes_dispatcher_service_before_dependent_module_starts() {
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(LinkMessageModule::new()));
    kernel.register(Box::new(DispatcherWiringProbe { wired: false }));

    kernel.start().unwrap();
}

struct LinkConsumerModule {
    decoded_families: Vec<&'static str>,
}

impl RuntimeModule for LinkConsumerModule {
    fn name(&self) -> &'static str {
        "link-consumer"
    }

    fn required_service_keys(&self) -> &[ServiceKey] {
        const KEYS: &[ServiceKey] = &[ServiceKey::of::<LinkMessageDispatcher>(
            LINK_MESSAGE_DISPATCHER_SERVICE_KEY,
        )];
        KEYS
    }

    fn wire(&mut self, services: &ServiceRegistry) -> Result<(), ModuleError> {
        let identity = make_identity("consumer");
        let dispatcher = services
            .get::<LinkMessageDispatcher>()
            .ok_or_else(|| ModuleError::Lifecycle("missing LinkMessageDispatcher".to_string()))?;

        let path = dispatcher
            .decode_verified(&encoded_path_control(&identity))
            .expect("path-control should decode");
        match path {
            AuthenticatedLinkMessage::PathControl(_) => self.decoded_families.push("path-control"),
            _ => {
                return Err(ModuleError::Lifecycle(
                    "unexpected family while decoding path-control".to_string(),
                ));
            }
        }

        let init = dispatcher
            .decode_verified(&encoded_session_init(&identity))
            .expect("session-init should decode");
        match init {
            AuthenticatedLinkMessage::SessionInit(_) => self.decoded_families.push("session-init"),
            _ => {
                return Err(ModuleError::Lifecycle(
                    "unexpected family while decoding session-init".to_string(),
                ));
            }
        }

        let accept = dispatcher
            .decode_verified(&encoded_session_accept(&identity))
            .expect("session-accept should decode");
        match accept {
            AuthenticatedLinkMessage::SessionAccept(_) => {
                self.decoded_families.push("session-accept")
            }
            _ => {
                return Err(ModuleError::Lifecycle(
                    "unexpected family while decoding session-accept".to_string(),
                ));
            }
        }

        let switch = dispatcher
            .decode_verified(&encoded_session_path_switch(&identity))
            .expect("session-path-switch should decode");
        match switch {
            AuthenticatedLinkMessage::SessionPathSwitch(_) => {
                self.decoded_families.push("session-path-switch")
            }
            _ => {
                return Err(ModuleError::Lifecycle(
                    "unexpected family while decoding session-path-switch".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        assert_eq!(
            self.decoded_families,
            [
                "path-control",
                "session-init",
                "session-accept",
                "session-path-switch",
            ]
        );
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }
}

#[test]
fn dependent_module_decodes_all_link_message_families_through_dispatcher_service() {
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(LinkMessageModule::new()));
    kernel.register(Box::new(LinkConsumerModule {
        decoded_families: Vec::new(),
    }));

    kernel.start().unwrap();
}

struct DispatcherContractModule;

impl RuntimeModule for DispatcherContractModule {
    fn name(&self) -> &'static str {
        "dispatcher-contract"
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

#[test]
fn kernel_rejects_missing_dispatcher_dependency_when_link_module_not_registered() {
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(DispatcherContractModule));

    let error = kernel.start().unwrap_err();

    assert!(error.to_string().contains("dispatcher-contract"));
    assert!(
        error
            .to_string()
            .contains(LINK_MESSAGE_DISPATCHER_SERVICE_KEY)
    );
}
