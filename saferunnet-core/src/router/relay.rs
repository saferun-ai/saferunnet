use std::sync::Arc;

use crate::vpn::ExitPolicy;
use crate::link::{FrameKind, LlarpFrame};
use crate::path::transit_hop::AuthenticatedTransitHopMessage;
use thiserror::Error;

use crate::router::onion::{ONION_LAYER_SIZE, OnionError, OnionRouter};

/// Handles relay (transit) logic: receives onion-encrypted frames,
/// peels one layer, and prepares the inner frame for forwarding.
pub struct RelayHandler {
    onion: OnionRouter,
    exit_policy: Option<Arc<dyn ExitPolicy + Send + Sync>>,
}

impl std::fmt::Debug for RelayHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayHandler")
            .field("onion", &self.onion)
            .field(
                "exit_policy",
                &self.exit_policy.as_ref().map(|_| "<opaque>"),
            )
            .finish()
    }
}

impl Clone for RelayHandler {
    fn clone(&self) -> Self {
        Self {
            onion: self.onion.clone(),
            exit_policy: None, // trait objects can"t be cloned generically
        }
    }
}

impl RelayHandler {
    pub fn new() -> Self {
        Self {
            onion: OnionRouter::new(),
            exit_policy: None,
        }
    }

    /// Set an exit policy for egress filtering at the final hop.
    pub fn with_exit_policy<P: ExitPolicy + Send + Sync + 'static>(mut self, policy: P) -> Self {
        self.exit_policy = Some(Arc::new(policy));
        self
    }

    /// Check if traffic to a target is allowed by the exit policy.
    pub fn check_exit(&self, target: &str, port: u16) -> Result<(), RelayError> {
        if let Some(ref policy) = self.exit_policy {
            policy
                .allows(target, port)
                .map_err(|e| RelayError::ExitPolicyDenied {
                    target: target.to_string(),
                    port,
                    reason: e.to_string(),
                })?;
        }
        Ok(())
    }

    /// Process an incoming relay frame by peeling the outermost onion layer.
    ///
    /// Returns the inner LLARP frame that should be forwarded to the next hop,
    /// or the decrypted plaintext if this is the final hop (exit node).
    pub fn handle_relay(
        &self,
        frame: &LlarpFrame,
        hop_public_key: &saferunnet_crypto::PublicKey,
        session_nonce: &[u8; ONION_LAYER_SIZE],
        total_hops: usize,
    ) -> Result<RelayResult, RelayError> {
        match frame.kind {
            FrameKind::RelayIntro => {
                // RelayIntro: first-hop setup. Decrypt intro payload.
                let inner = self.onion.unwrap(
                    hop_public_key,
                    session_nonce,
                    frame.hop_index as usize,
                    &frame.payload,
                );
                Ok(RelayResult::Forward {
                    next_frame: LlarpFrame::new(
                        FrameKind::RelayData,
                        frame.path_id,
                        frame.hop_index.wrapping_add(1),
                        inner?,
                    )?,
                })
            }
            FrameKind::RelayData => {
                let inner = self.onion.unwrap(
                    hop_public_key,
                    session_nonce,
                    frame.hop_index as usize,
                    &frame.payload,
                )?;

                // Only check exit policy at the final hop.
                if self.is_exit_hop(frame, total_hops) {
                    if let Ok((target, port)) = crate::vpn::parse_exit_target(&inner) {
                        self.check_exit(&target, port)?;
                        return Ok(RelayResult::Exit { plaintext: inner });
                    }
                }

                // Not the exit hop, or not an exit target — forward to next hop
                Ok(RelayResult::Forward {
                    next_frame: LlarpFrame::new(
                        FrameKind::RelayData,
                        frame.path_id,
                        frame.hop_index.wrapping_add(1),
                        inner,
                    )?,
                })
            }
            FrameKind::SessionData => {
                // Session data is end-to-end; relay should not peel it.
                // Forward as-is to the next hop.
                Ok(RelayResult::Forward {
                    next_frame: frame.clone(),
                })
            }
            FrameKind::Control => {
                // Control frames pass through unmodified.
                Ok(RelayResult::Forward {
                    next_frame: frame.clone(),
                })
            }
        }
    }

    /// Determine if this frame has reached its final hop.
    /// Callers should check this to decide whether to decrypt inner payload as exit.
    pub fn is_exit_hop(&self, frame: &LlarpFrame, total_hops: usize) -> bool {
        frame.hop_index as usize + 1 >= total_hops
    }

    /// Wrap an authenticated transit hop message into a relay frame.
    pub fn wrap_transit_hop(
        &self,
        message: &AuthenticatedTransitHopMessage,
        path_id: u64,
        hop_index: u8,
    ) -> Result<LlarpFrame, RelayError> {
        let encoded = message.encode()?;
        LlarpFrame::new(FrameKind::RelayData, path_id, hop_index, encoded).map_err(Into::into)
    }
}

impl Default for RelayHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of relay processing.
#[derive(Debug, Clone)]
pub enum RelayResult {
    /// Forward this frame to the next hop.
    Forward { next_frame: LlarpFrame },
    /// This is the exit hop: decrypted payload ready for egress.
    Exit { plaintext: Vec<u8> },
}

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("relay frame error: {0}")]
    Frame(#[from] crate::link::FrameCodecError),
    #[error("onion crypto error: {0}")]
    Onion(#[from] OnionError),
    #[error("transit hop encode error: {0}")]
    TransitHop(String),
    #[error("exit policy denied traffic to {target}:{port}: {reason}")]
    ExitPolicyDenied {
        target: String,
        port: u16,
        reason: String,
    },
}

impl From<crate::path::transit_hop::TransitHopError> for RelayError {
    fn from(e: crate::path::transit_hop::TransitHopError) -> Self {
        RelayError::TransitHop(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::onion::OnionRouter;
    use saferunnet_crypto::{KeyAlgorithm, PublicKey};

    fn make_key(seed: u8) -> PublicKey {
        PublicKey::from_bytes(KeyAlgorithm::Ed25519, [seed; 32])
    }

    fn make_nonce(seed: u8) -> [u8; 32] {
        let mut n = [0u8; 32];
        n[0] = seed;
        n
    }

    #[test]
    fn relay_intro_produces_relay_data() {
        let onion = OnionRouter::new();
        let handler = RelayHandler::new();
        let hops = vec![make_key(1), make_key(2)];
        let nonce = make_nonce(42);

        // Build a proper onion-wrapped payload
        let wrapped = onion.wrap(&hops, &nonce, b"intro").unwrap();
        let frame = LlarpFrame::new(FrameKind::RelayIntro, 1, 0, wrapped).unwrap();

        let result = handler.handle_relay(&frame, &hops[0], &nonce, 2).unwrap();
        match result {
            RelayResult::Forward { next_frame } => {
                assert_eq!(next_frame.kind, FrameKind::RelayData);
                assert_eq!(next_frame.path_id, 1);
                assert_eq!(next_frame.hop_index, 1);
            }
            RelayResult::Exit { .. } => panic!("unexpected Exit for relay intro"),
        }
    }

    #[test]
    fn control_passes_through() {
        let handler = RelayHandler::new();
        let frame = LlarpFrame::new(FrameKind::Control, 5, 0, b"ping".to_vec()).unwrap();
        let result = handler
            .handle_relay(&frame, &make_key(1), &make_nonce(1), 1)
            .unwrap();
        match result {
            RelayResult::Forward { next_frame } => {
                assert_eq!(next_frame.kind, FrameKind::Control);
                assert_eq!(next_frame.payload, b"ping");
            }
            RelayResult::Exit { .. } => panic!("unexpected Exit for control frame"),
        }
    }

    #[test]
    fn session_data_passes_through() {
        let handler = RelayHandler::new();
        let frame = LlarpFrame::new(FrameKind::SessionData, 3, 1, b"end_to_end".to_vec()).unwrap();
        let result = handler
            .handle_relay(&frame, &make_key(1), &make_nonce(1), 1)
            .unwrap();
        match result {
            RelayResult::Forward { next_frame } => {
                assert_eq!(next_frame.kind, FrameKind::SessionData);
                assert_eq!(next_frame.payload, b"end_to_end");
            }
            RelayResult::Exit { .. } => panic!("unexpected Exit for session data"),
        }
    }

    #[test]
    fn is_exit_hop_detection() {
        let handler = RelayHandler::new();
        let frame = LlarpFrame::new(FrameKind::RelayData, 1, 2, b"data".to_vec()).unwrap();
        assert!(!handler.is_exit_hop(&frame, 5));
        assert!(handler.is_exit_hop(&frame, 3));
    }

    #[test]
    fn relay_data_increments_hop_index() {
        let onion = OnionRouter::new();
        let handler = RelayHandler::new();
        let hops = vec![make_key(1), make_key(2)];
        let nonce = make_nonce(1);

        let wrapped = onion.wrap(&hops, &nonce, b"onion_data").unwrap();
        let frame = LlarpFrame::new(FrameKind::RelayData, 7, 0, wrapped).unwrap();
        let result = handler.handle_relay(&frame, &hops[0], &nonce, 2).unwrap();
        match result {
            RelayResult::Forward { next_frame } => {
                assert_eq!(next_frame.hop_index, 1);
                assert_eq!(next_frame.path_id, 7);
                assert_eq!(next_frame.kind, FrameKind::RelayData);
            }
            RelayResult::Exit { .. } => panic!("unexpected Exit for relay data"),
        }
    }
}
