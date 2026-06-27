use saferunnet_app::{
    AppKernel, LINK_MESSAGE_DISPATCHER_SERVICE_KEY, LinkMessageModule, LinkSessionStateModule,
    SessionCoordinatorModule,
};
use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator};
use saferunnet_identity::NodeIdentity;
use saferunnet_service::SessionTag;

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

#[test]
fn coordinator_registers_via_kernel() {
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(LinkMessageModule::new()));
    kernel.register(Box::new(LinkSessionStateModule::default()));
    kernel.register(Box::new(SessionCoordinatorModule::new()));
    kernel.start().unwrap();
    assert_eq!(kernel.state(), saferunnet_core::LifecycleState::Running);
    kernel.stop().unwrap();
}

#[test]
fn coordinator_requires_dispatcher_and_state() {
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(SessionCoordinatorModule::new()));
    let result = kernel.start();
    assert!(result.is_err());
}

#[test]
fn coordinator_wires_dispatcher() {
    let mut kernel = AppKernel::new();
    kernel.register(Box::new(LinkMessageModule::new()));
    kernel.register(Box::new(LinkSessionStateModule::default()));
    let coordinator = SessionCoordinatorModule::new();
    kernel.register(Box::new(coordinator));
    kernel.start().unwrap();

    // Verify the dispatcher exists and can decode messages
    let dispatcher = kernel
        .services()
        .get_named::<saferunnet_app::LinkMessageDispatcher>(LINK_MESSAGE_DISPATCHER_SERVICE_KEY)
        .unwrap();

    let identity = make_identity("test");
    let accept_msg = saferunnet_service::AuthenticatedSessionAcceptMessage::sign(
        &identity,
        saferunnet_service::SessionAcceptMessage {
            session_tag: SessionTag::new(42),
        },
    )
    .unwrap();
    let encoded = accept_msg.encode().unwrap();
    let decoded = dispatcher.decode_verified(&encoded).unwrap();
    assert!(matches!(
        decoded,
        saferunnet_service::AuthenticatedLinkMessage::SessionAccept(_)
    ));

    kernel.stop().unwrap();
}
