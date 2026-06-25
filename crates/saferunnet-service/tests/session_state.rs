use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator};
use saferunnet_identity::NodeIdentity;
use saferunnet_service::{
    ActiveSession, SessionAcceptMessage, SessionHopId, SessionInitMessage,
    SessionPathSwitchMessage, SessionState, SessionStateError, SessionTag,
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

fn init_message(identity: &NodeIdentity) -> SessionInitMessage {
    SessionInitMessage {
        initiator: identity.public_key.clone(),
        local_pivot: hop(0x11),
        remote_pivot: hop(0x22),
        auth_token: Some(vec![0xaa, 0xbb]),
    }
}

#[test]
fn record_pending_init_accept_and_path_switch_produce_updated_active_session() {
    let identity = make_identity("alice");
    let init = init_message(&identity);
    let accept = SessionAcceptMessage {
        session_tag: SessionTag::new(77),
    };
    let path_switch = SessionPathSwitchMessage {
        local_pivot: hop(0x33),
        remote_pivot: hop(0x44),
        session_tag: SessionTag::new(77),
    };

    let mut state = SessionState::new();
    state.record_pending_init(init.clone());

    assert_eq!(state.pending_init_count(), 1);

    state
        .accept_pending_init(&init, &accept)
        .expect("pending init should promote");

    assert_eq!(state.pending_init_count(), 0);
    assert_eq!(state.active_session_count(), 1);
    assert_eq!(
        state.active_session(SessionTag::new(77)),
        Some(ActiveSession {
            initiator: identity.public_key.clone(),
            local_pivot: hop(0x11),
            remote_pivot: hop(0x22),
            auth_token: Some(vec![0xaa, 0xbb]),
            session_tag: SessionTag::new(77),
        })
    );

    state
        .apply_path_switch(&path_switch)
        .expect("active session should switch paths");

    assert_eq!(
        state.active_session(SessionTag::new(77)),
        Some(ActiveSession {
            initiator: identity.public_key,
            local_pivot: hop(0x33),
            remote_pivot: hop(0x44),
            auth_token: Some(vec![0xaa, 0xbb]),
            session_tag: SessionTag::new(77),
        })
    );
}

#[test]
fn accept_requires_matching_pending_init() {
    let identity = make_identity("alice");
    let init = init_message(&identity);
    let accept = SessionAcceptMessage {
        session_tag: SessionTag::new(7),
    };

    let error = SessionState::new()
        .accept_pending_init(&init, &accept)
        .expect_err("accept should require pending init");

    assert!(matches!(error, SessionStateError::PendingInitNotFound));
}

#[test]
fn accept_rejects_duplicate_active_session_tag() {
    let alice = make_identity("alice");
    let bob = make_identity("bob");
    let alice_init = init_message(&alice);
    let bob_init = init_message(&bob);
    let accept = SessionAcceptMessage {
        session_tag: SessionTag::new(7),
    };

    let mut state = SessionState::new();
    state.record_pending_init(alice_init.clone());
    state.record_pending_init(bob_init.clone());

    state
        .accept_pending_init(&alice_init, &accept)
        .expect("first accept should promote");

    let error = state
        .accept_pending_init(&bob_init, &accept)
        .expect_err("duplicate active session tag should be rejected");

    assert_eq!(
        error,
        SessionStateError::SessionTagAlreadyActive(SessionTag::new(7))
    );
    assert_eq!(state.pending_init_count(), 1);
    assert_eq!(state.active_session_count(), 1);
    assert_eq!(
        state.active_session(SessionTag::new(7)),
        Some(ActiveSession {
            initiator: alice.public_key,
            local_pivot: hop(0x11),
            remote_pivot: hop(0x22),
            auth_token: Some(vec![0xaa, 0xbb]),
            session_tag: SessionTag::new(7),
        })
    );
}

#[test]
fn path_switch_requires_existing_active_session() {
    let path_switch = SessionPathSwitchMessage {
        local_pivot: hop(0x33),
        remote_pivot: hop(0x44),
        session_tag: SessionTag::new(88),
    };

    let error = SessionState::new()
        .apply_path_switch(&path_switch)
        .expect_err("path switch should require active session");

    assert!(matches!(error, SessionStateError::ActiveSessionNotFound));
}
