use saferunnet_crypto::PublicKey;
use saferunnet_service::SessionTag;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session not in expected state: {0:?}")]
    WrongState(SessionState),
    #[error("session expired")]
    Expired,
    #[error("invalid session tag")]
    InvalidTag,
}

/// State of a link session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is being initiated.
    Initiating,
    /// Session is established and active.
    Active,
    /// Session path is being switched.
    PathSwitching,
    /// Session has been closed.
    Closed,
}

/// A link-layer session between two peers.
#[derive(Debug, Clone)]
pub struct LinkSession {
    pub tag: SessionTag,
    pub remote: PublicKey,
    pub state: SessionState,
    pub created_at: u64,
}

impl LinkSession {
    pub fn new(tag: SessionTag, remote: PublicKey, now: u64) -> Self {
        Self {
            tag,
            remote,
            state: SessionState::Initiating,
            created_at: now,
        }
    }

    pub fn accept(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::Initiating {
            return Err(SessionError::WrongState(self.state));
        }
        self.state = SessionState::Active;
        Ok(())
    }

    pub fn switch_path(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::Active {
            return Err(SessionError::WrongState(self.state));
        }
        self.state = SessionState::PathSwitching;
        Ok(())
    }

    pub fn complete_switch(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::PathSwitching {
            return Err(SessionError::WrongState(self.state));
        }
        self.state = SessionState::Active;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::Closed {
            return Err(SessionError::WrongState(self.state));
        }
        self.state = SessionState::Closed;
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            SessionState::Active | SessionState::PathSwitching
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session() -> LinkSession {
        let pk_bytes = [0xabu8; 32];
        let pk = PublicKey::from_bytes(saferunnet_crypto::KeyAlgorithm::Ed25519, pk_bytes);
        LinkSession::new(SessionTag::new(1), pk, 0)
    }

    #[test]
    fn session_lifecycle() {
        let mut session = make_session();
        assert_eq!(session.state, SessionState::Initiating);

        session.accept().unwrap();
        assert!(session.is_active());

        session.switch_path().unwrap();
        assert_eq!(session.state, SessionState::PathSwitching);

        session.complete_switch().unwrap();
        assert!(session.is_active());

        session.close().unwrap();
        assert_eq!(session.state, SessionState::Closed);
    }

    #[test]
    fn session_rejects_accept_when_not_initiating() {
        let mut session = make_session();
        session.accept().unwrap(); // Now active
        let result = session.accept();
        assert!(result.is_err());
    }

    #[test]
    fn session_rejects_double_close() {
        let mut session = make_session();
        session.close().unwrap();
        let result = session.close();
        assert!(result.is_err());
    }
}
