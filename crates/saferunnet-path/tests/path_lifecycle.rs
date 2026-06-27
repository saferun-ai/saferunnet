use saferunnet_crypto::PublicKey;
use saferunnet_path::build::{PathBuilder, RandomPathBuilder};
use saferunnet_path::health::{PathHealthChecker, PingHealthChecker};
use saferunnet_path::select::{FirstAvailableSelector, PathSelector};
use saferunnet_path::{PathDescriptor, PathError, PathState};

fn make_key(seed: u8) -> PublicKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    saferunnet_crypto::PublicKey::from_bytes(saferunnet_crypto::KeyAlgorithm::Ed25519, bytes)
}

#[test]
fn build_path_creates_descriptor_with_hops() {
    let pool = vec![make_key(1), make_key(2), make_key(3)];
    let mut builder = RandomPathBuilder::new(pool);
    let target = make_key(0xff);
    let result = builder.build_path(&target, 2).expect("build path");
    assert_eq!(result.path_id, 1);
    assert_eq!(result.hops.len(), 3);
    assert_eq!(result.hops[2], target);
    assert_eq!(result.state, PathState::Building);
}

#[test]
fn build_path_rejects_zero_hops() {
    let pool = vec![make_key(1)];
    let mut builder = RandomPathBuilder::new(pool);
    let target = make_key(0xff);
    let err = builder
        .build_path(&target, 0)
        .expect_err("should reject zero hops");
    assert!(matches!(err, PathError::EmptyHops));
}

#[test]
fn build_path_rejects_too_many_hops() {
    let pool = vec![make_key(1), make_key(2)];
    let mut builder = RandomPathBuilder::new(pool);
    let target = make_key(0xff);
    let err = builder
        .build_path(&target, 3)
        .expect_err("should reject too many hops");
    assert!(matches!(err, PathError::TooManyHops(3, 2)));
}

#[test]
fn build_path_assigns_incrementing_ids() {
    let pool = vec![make_key(1), make_key(2), make_key(3)];
    let mut builder = RandomPathBuilder::new(pool);
    let target = make_key(0xff);
    let p1 = builder.build_path(&target, 1).expect("build path 1");
    let p2 = builder.build_path(&target, 1).expect("build path 2");
    assert_eq!(p1.path_id, 1);
    assert_eq!(p2.path_id, 2);
}

#[test]
fn selector_finds_established_path() {
    let mut selector = FirstAvailableSelector::new();
    let target = make_key(0xff);
    let path = PathDescriptor {
        path_id: 1,
        hops: vec![make_key(1), target.clone()],
        state: PathState::Established,
    };
    selector.insert(path);
    let found = selector.select_path(&target).expect("should find path");
    assert_eq!(found.path_id, 1);
}

#[test]
fn selector_ignores_building_paths() {
    let mut selector = FirstAvailableSelector::new();
    let target = make_key(0xff);
    let path = PathDescriptor {
        path_id: 1,
        hops: vec![make_key(1), target.clone()],
        state: PathState::Building,
    };
    selector.insert(path);
    assert!(selector.select_path(&target).is_none());
}

#[test]
fn selector_ignores_dead_paths() {
    let mut selector = FirstAvailableSelector::new();
    let target = make_key(0xff);
    let path = PathDescriptor {
        path_id: 1,
        hops: vec![make_key(1), target.clone()],
        state: PathState::Dead,
    };
    selector.insert(path);
    assert!(selector.select_path(&target).is_none());
}

#[test]
fn selector_removes_path() {
    let mut selector = FirstAvailableSelector::new();
    let target = make_key(0xff);
    let path = PathDescriptor {
        path_id: 42,
        hops: vec![make_key(1), target.clone()],
        state: PathState::Established,
    };
    selector.insert(path);
    selector.remove(42);
    assert!(selector.select_path(&target).is_none());
}

#[test]
fn health_check_failing_becomes_dead() {
    let mut checker = PingHealthChecker::new();
    let path = PathDescriptor {
        path_id: 1,
        hops: vec![make_key(1)],
        state: PathState::Failing,
    };
    assert_eq!(checker.check(&path), PathState::Dead);
}

#[test]
fn health_check_established_stays_established() {
    let mut checker = PingHealthChecker::new();
    let path = PathDescriptor {
        path_id: 1,
        hops: vec![make_key(1)],
        state: PathState::Established,
    };
    assert_eq!(checker.check(&path), PathState::Established);
}
