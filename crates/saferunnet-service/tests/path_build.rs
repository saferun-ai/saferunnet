use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator};
use saferunnet_identity::NodeIdentity;
use saferunnet_service::{
    AuthenticatedPathBuildMessage, AuthenticatedPathBuildResponse, AuthenticatedServiceMessage,
    PathBuildMessage, PathBuildResponse, PathHop, ServiceMessageKind,
};

fn make_identity(nickname: &str) -> NodeIdentity {
    let key_pair = Ed25519KeyGenerator::new()
        .generate(KeyAlgorithm::Ed25519)
        .expect("test key generation");
    NodeIdentity {
        nickname: nickname.to_string(),
        algorithm: KeyAlgorithm::Ed25519,
        secret_key: key_pair.secret_key,
        public_key: key_pair.public_key,
    }
}

#[test]
fn sign_verify_round_trip() {
    let id = make_identity("alice");
    let msg = PathBuildMessage {
        path_id: 42,
        hops: vec![PathHop {
            router_id: id.public_key.clone(),
        }],
    };
    let signed = AuthenticatedPathBuildMessage::sign(&id, msg).expect("sign");
    signed.verify().expect("verify");
}

#[test]
fn encode_decode_round_trip() {
    let id = make_identity("alice");
    let msg = PathBuildMessage {
        path_id: 42,
        hops: vec![PathHop {
            router_id: id.public_key.clone(),
        }],
    };
    let signed = AuthenticatedPathBuildMessage::sign(&id, msg).expect("sign");
    let encoded = signed.encode().expect("encode");
    let decoded = AuthenticatedPathBuildMessage::decode(&encoded).expect("decode");
    assert_eq!(signed.message(), decoded.message());
}

#[test]
fn reject_wrong_service_kind() {
    let id = make_identity("alice");
    let msg = PathBuildMessage {
        path_id: 1,
        hops: vec![PathHop {
            router_id: id.public_key.clone(),
        }],
    };
    let body = msg.encode().expect("encode");
    let inner = AuthenticatedServiceMessage::sign(&id, ServiceMessageKind::LinkPathControl, body)
        .expect("sign");
    let encoded = inner.encode().expect("encode");
    assert!(AuthenticatedPathBuildMessage::decode(&encoded).is_err());
}

#[test]
fn reject_empty_hops() {
    assert!(
        PathBuildMessage {
            path_id: 1,
            hops: vec![]
        }
        .encode()
        .is_err()
    );
}

#[test]
fn reject_too_many_hops() {
    let id = make_identity("alice");
    let pk = id.public_key.clone();
    let hops: Vec<_> = (0..9)
        .map(|_| PathHop {
            router_id: pk.clone(),
        })
        .collect();
    assert!(PathBuildMessage { path_id: 1, hops }.encode().is_err());
}

#[test]
fn reject_unsupported_version() {
    let mut encoded = vec![99u8, 1, 0, 0, 0, 0, 0, 0, 0, 1];
    encoded.extend_from_slice(&[0u8; 32]);
    assert!(PathBuildMessage::decode(&encoded).is_err());
}

#[test]
fn reject_truncated() {
    assert!(PathBuildMessage::decode(&[1, 2]).is_err());
}

#[test]
fn reject_trailing_bytes() {
    let id = make_identity("alice");
    let mut encoded = vec![1u8, 1, 0, 0, 0, 0, 0, 0, 0, 1];
    encoded.extend_from_slice(&id.public_key.to_bytes());
    encoded.push(0xee);
    assert!(PathBuildMessage::decode(&encoded).is_err());
}

#[test]
fn response_sign_verify_round_trip() {
    let id = make_identity("alice");
    let resp = PathBuildResponse {
        path_id: 42,
        accepted: true,
    };
    let signed = AuthenticatedPathBuildResponse::sign(&id, resp).expect("sign");
    signed.verify().expect("verify");
}

#[test]
fn response_encode_decode_round_trip() {
    let id = make_identity("alice");
    let resp = PathBuildResponse {
        path_id: 42,
        accepted: false,
    };
    let signed = AuthenticatedPathBuildResponse::sign(&id, resp).expect("sign");
    let encoded = signed.encode().expect("encode");
    let decoded = AuthenticatedPathBuildResponse::decode(&encoded).expect("decode");
    assert_eq!(signed.message(), decoded.message());
}

#[test]
fn response_reject_wrong_kind() {
    let id = make_identity("alice");
    let resp = PathBuildResponse {
        path_id: 1,
        accepted: true,
    };
    let body = resp.encode().expect("encode");
    let inner = AuthenticatedServiceMessage::sign(&id, ServiceMessageKind::LinkPathControl, body)
        .expect("sign");
    let encoded = inner.encode().expect("encode");
    assert!(AuthenticatedPathBuildResponse::decode(&encoded).is_err());
}

#[test]
fn response_reject_invalid_accepted_byte() {
    let encoded = [1u8, 0, 0, 0, 0, 0, 0, 0, 1, 99];
    assert!(PathBuildResponse::decode(&encoded).is_err());
}

#[test]
fn response_reject_truncated() {
    assert!(PathBuildResponse::decode(&[]).is_err());
}

#[test]
fn response_reject_unsupported_version() {
    let encoded = [99u8, 0, 0, 0, 0, 0, 0, 0, 1, 1];
    assert!(PathBuildResponse::decode(&encoded).is_err());
}

#[test]
fn response_reject_trailing_bytes() {
    let mut encoded = vec![1u8, 0, 0, 0, 0, 0, 0, 0, 1, 1];
    encoded.push(0xee);
    assert!(PathBuildResponse::decode(&encoded).is_err());
}
