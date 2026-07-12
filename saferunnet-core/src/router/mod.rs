pub mod onion;
pub mod path_build;
pub mod route_poker;
pub mod relay;
pub mod router_announcement;
pub mod router_types;

pub use onion::{OnionError, OnionLayer, OnionRouter, ONION_LAYER_SIZE};
pub use path_build::{PathBuildError, PathBuilder, PathHopSpec};
pub use relay::{RelayError, RelayHandler, RelayResult};
pub use router_types::{BootstrapPhase, RouterConfig, RouterState};

/// Threshold for network reset detection (backward time jump > 30 seconds).
pub const NETWORK_RESET_THRESHOLD_SECS: u64 = 30;

/// Detect a network reset by checking for backward time jumps.
/// Returns 	rue if a backward jump exceeding the threshold is detected.
pub fn detect_network_reset(last_known: &mut Option<std::time::Instant>) -> bool {
    let now = std::time::Instant::now();
    if let Some(prev) = *last_known {
        if now < prev {
            let diff = prev.duration_since(now);
            if diff.as_secs() > NETWORK_RESET_THRESHOLD_SECS {
                *last_known = Some(now);
                return true;
            }
        }
    }
    *last_known = Some(now);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_network_reset() {
        let mut last = Some(std::time::Instant::now());
        assert!(!detect_network_reset(&mut last));
    }

    #[test]
    fn test_first_call_sets_time() {
        let mut last: Option<std::time::Instant> = None;
        assert!(!detect_network_reset(&mut last));
        assert!(last.is_some());
    }

    #[test]
    fn test_small_forward_jump_no_reset() {
        let past = std::time::Instant::now() - std::time::Duration::from_secs(10);
        let mut last = Some(past);
        assert!(!detect_network_reset(&mut last));
    }
}
