use std::sync::{Arc, Mutex};

use saferunnet_app::{
    AppKernel, LINK_MESSAGE_DISPATCHER_SERVICE_KEY, LINK_SESSION_STATE_SERVICE_KEY,
    LinkMessageDispatcher, LinkMessageModule, LinkSessionState, LinkSessionStateModule,
};
use saferunnet_core::{ModuleError, RuntimeModule, ServiceKey, ServiceRegistry};
use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator};
use saferunnet_identity::NodeIdentity;
use saferunnet_service::{
    ActiveSession, AuthenticatedLinkMessage, AuthenticatedSessionAcceptMessage,
    AuthenticatedSessionCloseMessage, AuthenticatedSessionInitMessage,
    AuthenticatedSessionPathSwitchMessage, SessionAcceptMessage, SessionCloseMessage, SessionHopId,
    SessionInitMessage, SessionPathSwitchMessage, SessionTag,
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

fn encoded_session_close(identity: &NodeIdentity) -> Vec<u8> {
    AuthenticatedSessionCloseMessage::sign(
        identity,
        SessionCloseMessage {
            session_tag: SessionTag::new(77),
        },
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed")
}

struct LinkSessionLifecycleModule {
    identity: NodeIdentity,
    closed_session: Option<ActiveSession>,
    active_after_close: Option<ActiveSession>,
}

impl RuntimeModule for LinkSessionLifecycleModule {
    fn name(&self) -> &'static str {
        "link-session-lifecycle"
    }

    fn required_service_keys(&self) -> &[ServiceKey] {
        const KEYS: &[ServiceKey] = &[
            ServiceKey::of::<LinkMessageDispatcher>(LINK_MESSAGE_DISPATCHER_SERVICE_KEY),
            ServiceKey::of::<LinkSessionState>(LINK_SESSION_STATE_SERVICE_KEY),
        ];
        KEYS
    }

    fn wire(&mut self, services: &ServiceRegistry) -> Result<(), ModuleError> {
        let dispatcher = services
            .get::<LinkMessageDispatcher>()
            .ok_or_else(|| ModuleError::Lifecycle("missing LinkMessageDispatcher".to_string()))?;
        let state = services
            .get::<LinkSessionState>()
            .ok_or_else(|| ModuleError::Lifecycle("missing LinkSessionState".to_string()))?
            .clone();

        let init = dispatcher
            .decode_verified(&encoded_session_init(&self.identity))
            .expect("session-init should decode");
        let init_message = match init {
            AuthenticatedLinkMessage::SessionInit(inner) => inner.message().clone(),
            _ => {
                return Err(ModuleError::Lifecycle(
                    "unexpected family while decoding session-init".to_string(),
                ));
            }
        };
        state
            .lock()
            .expect("session state lock should not be poisoned")
            .record_pending_init(init_message.clone());

        let accept = dispatcher
            .decode_verified(&encoded_session_accept(&self.identity))
            .expect("session-accept should decode");
        let accept_message = match accept {
            AuthenticatedLinkMessage::SessionAccept(inner) => inner.message().clone(),
            _ => {
                return Err(ModuleError::Lifecycle(
                    "unexpected family while decoding session-accept".to_string(),
                ));
            }
        };
        state
            .lock()
            .expect("session state lock should not be poisoned")
            .accept_pending_init(&init_message, &accept_message)
            .map_err(|error| ModuleError::Lifecycle(error.to_string()))?;

        let switch = dispatcher
            .decode_verified(&encoded_session_path_switch(&self.identity))
            .expect("session-path-switch should decode");
        let switch_message = match switch {
            AuthenticatedLinkMessage::SessionPathSwitch(inner) => inner.message().clone(),
            _ => {
                return Err(ModuleError::Lifecycle(
                    "unexpected family while decoding session-path-switch".to_string(),
                ));
            }
        };
        let mut guard = state
            .lock()
            .expect("session state lock should not be poisoned");
        guard
            .apply_path_switch(&switch_message)
            .map_err(|error| ModuleError::Lifecycle(error.to_string()))?;
        let close = dispatcher
            .decode_verified(&encoded_session_close(&self.identity))
            .expect("session-close should decode");
        let close_message = match close {
            AuthenticatedLinkMessage::SessionClose(inner) => inner.message().clone(),
            _ => {
                return Err(ModuleError::Lifecycle(
                    "unexpected family while decoding session-close".to_string(),
                ));
            }
        };
        self.closed_session = Some(
            guard
                .close_active_session(&close_message)
                .map_err(|error| ModuleError::Lifecycle(error.to_string()))?,
        );
        self.active_after_close = guard.active_session(SessionTag::new(77));

        Ok(())
    }

    fn start(&mut self) -> Result<(), ModuleError> {
        assert_eq!(
            self.closed_session,
            Some(ActiveSession {
                initiator: self.identity.public_key.clone(),
                local_pivot: hop(0x33),
                remote_pivot: hop(0x44),
                auth_token: Some(vec![0xaa, 0xbb]),
                session_tag: SessionTag::new(77),
            })
        );
        assert_eq!(self.active_after_close, None);
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }
}

#[test]
fn runtime_consumer_drives_init_accept_path_switch_and_close_through_dispatcher_and_state_service()
{
    let identity = make_identity("consumer");
    let shared_state: LinkSessionState = Arc::new(Mutex::new(Default::default()));
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(LinkMessageModule::new()));
    kernel.register(Box::new(LinkSessionStateModule::from_shared_state(
        shared_state.clone(),
    )));
    kernel.register(Box::new(LinkSessionLifecycleModule {
        identity: NodeIdentity {
            nickname: identity.nickname.clone(),
            algorithm: identity.algorithm,
            secret_key: identity.secret_key.clone(),
            public_key: identity.public_key.clone(),
        },
        closed_session: None,
        active_after_close: None,
    }));

    kernel.start().expect("kernel should start");

    let final_session = shared_state
        .lock()
        .expect("session state lock should not be poisoned")
        .active_session(SessionTag::new(77));
    assert_eq!(final_session, None);
}
