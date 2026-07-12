use std::collections::HashMap;
use std::sync::RwLock;
use crate::session::SessionState;
use crate::session::{SessionInitMessage, SessionCloseMessage, SessionTag};
use crate::SessionHopId;

/// Manages active session lifecycle across paths.
/// Lokinet C++ equivalent: session tracking in llarp/router/
pub struct SessionManager {
    sessions: RwLock<HashMap<SessionTag, SessionState>>,
    hop_counter: RwLock<u64>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self { sessions: RwLock::new(HashMap::new()), hop_counter: RwLock::new(1) }
    }

    /// Record a pending session init from the network.
    /// Returns the assigned session tag.
    pub fn record_init(&self, msg: SessionInitMessage, tag: SessionTag) {
        let mut sessions = self.sessions.write().unwrap();
        let state = sessions.entry(tag).or_insert_with(SessionState::new);
        state.record_pending_init(msg);
    }

    /// Record a session close.
    pub fn record_close(&self, msg: SessionCloseMessage) -> Option<SessionState> {
        self.sessions.write().unwrap().remove(&msg.session_tag)
    }

    /// Mark a pending session as accepted.
    pub fn accept_session(&self, tag: &SessionTag) -> bool {
        if let Some(state) = self.sessions.write().unwrap().get_mut(tag) {
            if state.pending_init_count() > 0 {
                return true;
            }
        }
        false
    }

    /// Remove expired sessions.
    pub fn expire(&self, _now: u64) -> usize {
        // Stub: remove TTL-expired sessions
        0
    }

    /// Get active session count.
    pub fn active_count(&self) -> usize {
        self.sessions.read().unwrap().len()
    }

    /// List all active session tags.
    pub fn list_tags(&self) -> Vec<SessionTag> {
        self.sessions.read().unwrap().keys().cloned().collect()
    }

    /// Generate the next hop ID.
    pub fn next_hop_id(&self) -> SessionHopId {
        let mut counter = self.hop_counter.write().unwrap();
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&counter.to_be_bytes());
        *counter += 1;
        SessionHopId::new(bytes)
    }
}

impl Default for SessionManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionInitMessage;
    use saferunnet_crypto::{PublicKey, KeyAlgorithm};

    fn make_init_msg() -> SessionInitMessage {
        SessionInitMessage {
            initiator: PublicKey::from_bytes(KeyAlgorithm::Ed25519, [0u8; 32]),
            local_pivot: SessionHopId::new([1u8; 16]),
            remote_pivot: SessionHopId::new([2u8; 16]),
            auth_token: None,
        }
    }

    #[test]
    fn test_record_init_creates_state() {
        let mgr = SessionManager::new();
        let tag = SessionTag::new(42);
        let msg = make_init_msg();
        mgr.record_init(msg, tag);
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_record_close_removes_state() {
        let mgr = SessionManager::new();
        let tag = SessionTag::new(99);
        mgr.record_init(make_init_msg(), tag);
        let close = SessionCloseMessage { session_tag: tag };
        assert!(mgr.record_close(close).is_some());
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_list_tags() {
        let mgr = SessionManager::new();
        let t1 = SessionTag::new(1);
        let t2 = SessionTag::new(2);
        mgr.record_init(make_init_msg(), t1);
        mgr.record_init(make_init_msg(), t2);
        assert_eq!(mgr.list_tags().len(), 2);
    }

    #[test]
    fn test_next_hop_id_increments() {
        let mgr = SessionManager::new();
        let id1 = mgr.next_hop_id();
        let id2 = mgr.next_hop_id();
        assert_ne!(id1, id2);
    }
}
