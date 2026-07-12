use std::time::{Duration, Instant};
use crate::contact::RouterId;
use crate::session::{SessionHopId, SessionTag};

pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_QUEUED_PACKETS: usize = 30;
pub const SWITCH_XOR_FACTOR: u8 = 0x42;

pub type OnEstablishedCallback = Box<dyn FnOnce(SessionTag) + Send + 'static>;

// ── SessionCore ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SessionCore {
    pub inbound_tag: SessionTag,
    pub outbound_tag: SessionTag,
    pub remote_router_id: RouterId,
    pub is_established: bool,
    pub is_closed: bool,
    pub dead_path: bool,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub last_inbound_activity: Instant,
    pub remote_pivot_txid: SessionHopId,
    pub establish_timeout: Option<Duration>,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session is closed")]
    SessionClosed,
    #[error("session not established")]
    NotEstablished,
    #[error("no path available")]
    NoPath,
    #[error("queue full")]
    QueueFull,
}

impl SessionCore {
    pub fn new(
        inbound_tag: SessionTag,
        outbound_tag: SessionTag,
        remote_router_id: RouterId,
    ) -> Self {
        let now = Instant::now();
        Self {
            inbound_tag,
            outbound_tag,
            remote_router_id,
            is_established: false,
            is_closed: false,
            dead_path: true,
            created_at: now,
            last_activity: now,
            last_inbound_activity: now,
            remote_pivot_txid: SessionHopId::new([0u8; 16]),
            establish_timeout: None,
        }
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        if self.is_closed { return true; }
        if self.is_established { now.duration_since(self.last_activity) > SESSION_TIMEOUT }
        else if let Some(timeout) = self.establish_timeout { now.duration_since(self.created_at) > timeout }
        else { now.duration_since(self.created_at) > SESSION_TIMEOUT }
    }

    pub fn touch(&mut self) { self.last_activity = Instant::now(); }

    pub fn touch_inbound(&mut self) { self.last_inbound_activity = Instant::now(); }

    pub fn idle_duration(&self) -> Duration {
        Instant::now().duration_since(self.last_inbound_activity)
    }

    pub fn mark_established(&mut self) {
        self.is_established = true;
        self.touch();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_router_id(seed: u8) -> RouterId { RouterId([seed; 32]) }

    #[test]
    fn test_session_core_new() {
        let core = SessionCore::new(SessionTag::new(1), SessionTag::new(2), make_router_id(3));
        assert!(!core.is_established);
        assert!(!core.is_closed);
        assert!(core.dead_path);
    }

    #[test]
    fn test_session_core_touch() {
        let mut core = SessionCore::new(SessionTag::new(1), SessionTag::new(2), make_router_id(3));
        let before = core.last_activity;
        std::thread::sleep(Duration::from_millis(5));
        core.touch();
        assert!(core.last_activity > before);
    }

    #[test]
    fn test_session_core_touch_inbound() {
        let mut core = SessionCore::new(SessionTag::new(1), SessionTag::new(2), make_router_id(3));
        let before = core.last_inbound_activity;
        std::thread::sleep(Duration::from_millis(5));
        core.touch_inbound();
        assert!(core.last_inbound_activity > before);
    }

    #[test]
    fn test_session_core_idle_duration() {
        let core = SessionCore::new(SessionTag::new(1), SessionTag::new(2), make_router_id(3));
        let d = core.idle_duration();
        assert!(d.as_secs() < 1);
    }

    #[test]
    fn test_session_core_mark_established() {
        let mut core = SessionCore::new(SessionTag::new(1), SessionTag::new(2), make_router_id(3));
        core.mark_established();
        assert!(core.is_established);
    }
}
