use saferunnet_crypto::{
    Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator, SignatureError, SignedEnvelope,
    SignedEnvelopeCodec,
};
use saferunnet_identity::{IdentityProof, NodeIdentity};
use saferunnet_service::{
    AddressFamily, AuthenticatedDhtIntroMessage, AuthenticatedLinkMessage,
    AuthenticatedPathBuildMessage, AuthenticatedPathBuildResponse, AuthenticatedPathControlMessage,
    AuthenticatedServiceMessage, AuthenticatedSessionAcceptMessage,
    AuthenticatedSessionCloseMessage, AuthenticatedSessionInitMessage,
    AuthenticatedSessionPathSwitchMessage, AuthenticatedTransitHopMessage, DhtIntroEntry,
    DhtIntroMessage, LinkMessageError, PathBuildMessage, PathBuildResponse, PathControlMessage,
    PathHop, PathPing, ServiceMessageError, ServiceMessageKind, SessionAcceptMessage,
    SessionCloseError, SessionCloseMessage, SessionHopId, SessionInitError, SessionInitMessage,
    SessionPathSwitchError, SessionPathSwitchMessage, SessionTag, TransitHopMessage,
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

fn encode_top_frame(
    proof: &IdentityProof,
    envelope: &saferunnet_crypto::SignedEnvelope,
) -> Vec<u8> {
    let proof_bytes = proof
        .encode()
        .expect("identity proof encoding should succeed in tests");
    let envelope_bytes = SignedEnvelopeCodec::encode(envelope)
        .expect("signed envelope encoding should succeed in tests");
    let mut framed = Vec::with_capacity(1 + 4 + 4 + proof_bytes.len() + envelope_bytes.len());
    framed.push(1);
    framed.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(&(envelope_bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(&proof_bytes);
    framed.extend_from_slice(&envelope_bytes);
    framed
}

fn tamper_signed_service_payload(
    message: &AuthenticatedServiceMessage,
    mutate: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let proof = message.proof().clone();
    let mut tampered_payload = message.envelope().payload().to_vec();
    mutate(&mut tampered_payload);
    let tampered_envelope = SignedEnvelope::from_parts(
        tampered_payload,
        message.envelope().signer().clone(),
        message.envelope().signature().clone(),
    );
    encode_top_frame(&proof, &tampered_envelope)
}

#[test]
fn decode_dispatch_round_trip_path_control() {
    let identity = make_identity("alice");
    let encoded = AuthenticatedPathControlMessage::sign(
        &identity,
        PathControlMessage::Ping(PathPing { request_id: 4242 }),
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed");

    let decoded = AuthenticatedLinkMessage::decode(&encoded).expect("decode should succeed");
    match decoded {
        AuthenticatedLinkMessage::PathControl(inner) => {
            assert_eq!(
                inner.message(),
                &PathControlMessage::Ping(PathPing { request_id: 4242 })
            );
            inner.verify().expect("decoded path-control should verify");
        }
        _ => panic!("expected path-control variant"),
    }
}

#[test]
fn decode_dispatch_round_trip_session_init() {
    let identity = make_identity("alice");
    let encoded = AuthenticatedSessionInitMessage::sign(
        &identity,
        SessionInitMessage {
            initiator: identity.public_key.clone(),
            local_pivot: hop(0x11),
            remote_pivot: hop(0x22),
            auth_token: Some(vec![1, 2, 3, 4]),
        },
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed");

    let decoded = AuthenticatedLinkMessage::decode(&encoded).expect("decode should succeed");
    match decoded {
        AuthenticatedLinkMessage::SessionInit(inner) => {
            assert_eq!(inner.message().initiator, identity.public_key);
            assert_eq!(inner.message().local_pivot, hop(0x11));
            assert_eq!(inner.message().remote_pivot, hop(0x22));
            assert_eq!(inner.message().auth_token, Some(vec![1, 2, 3, 4]));
            inner.verify().expect("decoded session-init should verify");
        }
        _ => panic!("expected session-init variant"),
    }
}

#[test]
fn decode_dispatch_round_trip_session_accept() {
    let identity = make_identity("alice");
    let encoded = AuthenticatedSessionAcceptMessage::sign(
        &identity,
        SessionAcceptMessage {
            session_tag: SessionTag::new(55),
        },
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed");

    let decoded = AuthenticatedLinkMessage::decode(&encoded).expect("decode should succeed");
    match decoded {
        AuthenticatedLinkMessage::SessionAccept(inner) => {
            assert_eq!(inner.message().session_tag, SessionTag::new(55));
            inner
                .verify()
                .expect("decoded session-accept should verify");
        }
        _ => panic!("expected session-accept variant"),
    }
}

#[test]
fn decode_dispatch_round_trip_session_path_switch() {
    let identity = make_identity("alice");
    let encoded = AuthenticatedSessionPathSwitchMessage::sign(
        &identity,
        SessionPathSwitchMessage {
            local_pivot: hop(0x33),
            remote_pivot: hop(0x44),
            session_tag: SessionTag::new(77),
        },
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed");

    let decoded = AuthenticatedLinkMessage::decode(&encoded).expect("decode should succeed");
    match decoded {
        AuthenticatedLinkMessage::SessionPathSwitch(inner) => {
            assert_eq!(inner.message().local_pivot, hop(0x33));
            assert_eq!(inner.message().remote_pivot, hop(0x44));
            assert_eq!(inner.message().session_tag, SessionTag::new(77));
            inner
                .verify()
                .expect("decoded session-path-switch should verify");
        }
        _ => panic!("expected session-path-switch variant"),
    }
}

#[test]
fn decode_dispatch_round_trip_session_close() {
    let identity = make_identity("alice");
    let encoded = AuthenticatedSessionCloseMessage::sign(
        &identity,
        SessionCloseMessage {
            session_tag: SessionTag::new(77),
        },
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed");

    let decoded = AuthenticatedLinkMessage::decode(&encoded).expect("decode should succeed");
    match decoded {
        AuthenticatedLinkMessage::SessionClose(inner) => {
            assert_eq!(inner.message().session_tag, SessionTag::new(77));
            inner.verify().expect("decoded session-close should verify");
        }
        _ => panic!("expected session-close variant"),
    }
}

#[test]
fn non_link_service_kind_is_rejected_by_dispatcher() {
    let identity = make_identity("alice");
    let encoded =
        AuthenticatedServiceMessage::sign(&identity, ServiceMessageKind::Announcement, vec![1, 2])
            .expect("sign should succeed")
            .encode()
            .expect("encode should succeed");

    let error = AuthenticatedLinkMessage::decode(&encoded)
        .expect_err("non-link kind should be rejected by dispatcher");
    assert!(matches!(
        error,
        LinkMessageError::UnsupportedServiceKind(ServiceMessageKind::Announcement)
    ));
}

#[test]
fn verified_decode_prefers_authentication_failure_over_typed_parse_failure() {
    let identity = make_identity("alice");
    let signed = AuthenticatedSessionInitMessage::sign(
        &identity,
        SessionInitMessage {
            initiator: identity.public_key.clone(),
            local_pivot: hop(0x11),
            remote_pivot: hop(0x22),
            auth_token: None,
        },
    )
    .expect("sign should succeed");

    let encoded = tamper_signed_service_payload(signed.service_message(), |payload| {
        payload[7] = 0x7f;
    });

    let unverified_error = AuthenticatedLinkMessage::decode_unverified(&encoded)
        .expect_err("unverified decode should surface typed parse failure");
    assert!(matches!(
        unverified_error,
        LinkMessageError::SessionInit(SessionInitError::UnsupportedInitiatorAlgorithm(0x7f))
    ));

    let verified_error = AuthenticatedLinkMessage::decode(&encoded)
        .expect_err("verified decode should fail authentication first");
    assert!(matches!(
        verified_error,
        LinkMessageError::ServiceMessage(ServiceMessageError::Signature(
            SignatureError::VerificationFailed
        ))
    ));
}

#[test]
fn unverified_decode_surfaces_family_specific_typed_parse_error() {
    let identity = make_identity("alice");
    let signed = AuthenticatedSessionPathSwitchMessage::sign(
        &identity,
        SessionPathSwitchMessage {
            local_pivot: hop(0x11),
            remote_pivot: hop(0x22),
            session_tag: SessionTag::new(123),
        },
    )
    .expect("sign should succeed");

    let encoded = tamper_signed_service_payload(signed.service_message(), |payload| {
        payload[6] = 0x7f;
    });

    let error = AuthenticatedLinkMessage::decode_unverified(&encoded)
        .expect_err("unverified decode should surface typed parse failure");
    assert!(matches!(
        error,
        LinkMessageError::SessionPathSwitch(SessionPathSwitchError::UnsupportedPayloadVersion(
            0x7f
        ))
    ));
}

#[test]
fn unverified_decode_surfaces_session_close_typed_parse_error() {
    let identity = make_identity("alice");
    let signed = AuthenticatedSessionCloseMessage::sign(
        &identity,
        SessionCloseMessage {
            session_tag: SessionTag::new(456),
        },
    )
    .expect("sign should succeed");

    let encoded = tamper_signed_service_payload(signed.service_message(), |payload| {
        payload[6] = 0x7f;
    });

    let error = AuthenticatedLinkMessage::decode_unverified(&encoded)
        .expect_err("unverified decode should surface typed parse failure");
    assert!(matches!(
        error,
        LinkMessageError::SessionClose(SessionCloseError::UnsupportedPayloadVersion(0x7f))
    ));
}

#[test]
fn decode_dispatch_round_trip_dht_intro() {
    let identity = make_identity("alice");
    let entry = DhtIntroEntry {
        public_key: identity.public_key.clone(),
        family: AddressFamily::Ipv4,
        port: 8080,
    };
    let encoded = AuthenticatedDhtIntroMessage::sign(
        &identity,
        DhtIntroMessage {
            entries: vec![entry],
        },
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed");
    let decoded = AuthenticatedLinkMessage::decode(&encoded).expect("decode should succeed");
    match decoded {
        AuthenticatedLinkMessage::DhtIntro(inner) => {
            assert_eq!(inner.payload().entries.len(), 1);
            inner.verify().expect("decoded dht-intro should verify");
        }
        _ => panic!("expected dht-intro variant"),
    }
}

#[test]
fn decode_dispatch_round_trip_path_build() {
    let identity = make_identity("alice");
    let hop = PathHop {
        router_id: identity.public_key.clone(),
    };
    let encoded = AuthenticatedPathBuildMessage::sign(
        &identity,
        PathBuildMessage {
            path_id: 99,
            hops: vec![hop],
        },
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed");
    let decoded = AuthenticatedLinkMessage::decode(&encoded).expect("decode should succeed");
    match decoded {
        AuthenticatedLinkMessage::PathBuild(inner) => {
            assert_eq!(inner.message().path_id, 99);
            assert_eq!(inner.message().hops.len(), 1);
            inner.verify().expect("decoded path-build should verify");
        }
        _ => panic!("expected path-build variant"),
    }
}

#[test]
fn decode_dispatch_round_trip_path_build_response() {
    let identity = make_identity("alice");
    let encoded = AuthenticatedPathBuildResponse::sign(
        &identity,
        PathBuildResponse {
            path_id: 42,
            accepted: true,
        },
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed");
    let decoded = AuthenticatedLinkMessage::decode(&encoded).expect("decode should succeed");
    match decoded {
        AuthenticatedLinkMessage::PathBuildResponse(inner) => {
            assert_eq!(inner.message().path_id, 42);
            assert!(inner.message().accepted);
            inner
                .verify()
                .expect("decoded path-build-response should verify");
        }
        _ => panic!("expected path-build-response variant"),
    }
}

#[test]
fn decode_dispatch_round_trip_transit_hop() {
    let identity = make_identity("alice");
    let encoded = AuthenticatedTransitHopMessage::sign(
        &identity,
        TransitHopMessage {
            path_id: 7,
            hop_index: 3,
            encrypted_payload: vec![0xaa, 0xbb, 0xcc],
        },
    )
    .expect("sign should succeed")
    .encode()
    .expect("encode should succeed");
    let decoded = AuthenticatedLinkMessage::decode(&encoded).expect("decode should succeed");
    match decoded {
        AuthenticatedLinkMessage::TransitHop(inner) => {
            assert_eq!(inner.message().path_id, 7);
            assert_eq!(inner.message().hop_index, 3);
            assert_eq!(inner.message().encrypted_payload, vec![0xaa, 0xbb, 0xcc]);
            inner.verify().expect("decoded transit-hop should verify");
        }
        _ => panic!("expected transit-hop variant"),
    }
}
