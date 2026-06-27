use thiserror::Error;

use crate::session::{
    SessionAcceptMessage, SessionCloseMessage, SessionInitMessage, SessionPathSwitchMessage,
    SessionTag,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSession {
    pub initiator: saferunnet_crypto::PublicKey,
    pub local_pivot: crate::SessionHopId,
    pub remote_pivot: crate::SessionHopId,
    pub auth_token: Option<Vec<u8>>,
    pub session_tag: SessionTag,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SessionState {
    pending_inits: Vec<SessionInitMessage>,
    active_sessions: Vec<ActiveSession>,
}

impl SessionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_pending_init(&mut self, message: SessionInitMessage) {
        self.pending_inits.push(message);
    }

    pub fn pending_init_count(&self) -> usize {
        self.pending_inits.len()
    }

    pub fn active_session_count(&self) -> usize {
        self.active_sessions.len()
    }

    pub fn accept_pending_init(
        &mut self,
        init: &SessionInitMessage,
        accept: &SessionAcceptMessage,
    ) -> Result<(), SessionStateError> {
        if self
            .active_sessions
            .iter()
            .any(|session| session.session_tag == accept.session_tag)
        {
            return Err(SessionStateError::SessionTagAlreadyActive(
                accept.session_tag,
            ));
        }

        let pending_index = self
            .pending_inits
            .iter()
            .position(|pending| pending == init)
            .ok_or(SessionStateError::PendingInitNotFound)?;
        let pending = self.pending_inits.remove(pending_index);

        self.active_sessions.push(ActiveSession {
            initiator: pending.initiator,
            local_pivot: pending.local_pivot,
            remote_pivot: pending.remote_pivot,
            auth_token: pending.auth_token,
            session_tag: accept.session_tag,
        });
        Ok(())
    }

    pub fn apply_path_switch(
        &mut self,
        message: &SessionPathSwitchMessage,
    ) -> Result<(), SessionStateError> {
        let session = self
            .active_sessions
            .iter_mut()
            .find(|session| session.session_tag == message.session_tag)
            .ok_or(SessionStateError::ActiveSessionNotFound)?;
        session.local_pivot = message.local_pivot;
        session.remote_pivot = message.remote_pivot;
        Ok(())
    }

    pub fn close_active_session(
        &mut self,
        message: &SessionCloseMessage,
    ) -> Result<ActiveSession, SessionStateError> {
        let session_index = self
            .active_sessions
            .iter()
            .position(|session| session.session_tag == message.session_tag)
            .ok_or(SessionStateError::ActiveSessionNotFound)?;
        Ok(self.active_sessions.remove(session_index))
    }

    pub fn active_session(&self, session_tag: SessionTag) -> Option<ActiveSession> {
        self.active_sessions
            .iter()
            .find(|session| session.session_tag == session_tag)
            .cloned()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SessionStateError {
    #[error("session state has no matching pending init")]
    PendingInitNotFound,
    #[error("session state has no active session for that tag")]
    ActiveSessionNotFound,
    #[error("session state already has an active session for tag `{0:?}`")]
    SessionTagAlreadyActive(SessionTag),
}
