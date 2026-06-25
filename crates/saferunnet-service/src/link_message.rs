use thiserror::Error;

use crate::{
    AuthenticatedPathControlMessage, AuthenticatedServiceMessage, AuthenticatedSessionInitMessage,
    AuthenticatedSessionPathSwitchMessage, PathControlError, ServiceMessageError,
    ServiceMessageKind, SessionInitError, SessionPathSwitchError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatedLinkMessage {
    PathControl(AuthenticatedPathControlMessage),
    SessionInit(AuthenticatedSessionInitMessage),
    SessionPathSwitch(AuthenticatedSessionPathSwitchMessage),
}

impl AuthenticatedLinkMessage {
    pub fn decode(input: &[u8]) -> Result<Self, LinkMessageError> {
        Self::decode_verified(input)
    }

    pub fn decode_unverified(input: &[u8]) -> Result<Self, LinkMessageError> {
        let service_message = AuthenticatedServiceMessage::decode_unverified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn decode_verified(input: &[u8]) -> Result<Self, LinkMessageError> {
        let service_message = AuthenticatedServiceMessage::decode_verified(input)?;
        Self::from_authenticated_service_message(service_message)
    }

    pub fn service_message(&self) -> &AuthenticatedServiceMessage {
        match self {
            Self::PathControl(message) => message.service_message(),
            Self::SessionInit(message) => message.service_message(),
            Self::SessionPathSwitch(message) => message.service_message(),
        }
    }

    fn from_authenticated_service_message(
        service_message: AuthenticatedServiceMessage,
    ) -> Result<Self, LinkMessageError> {
        match service_message.kind() {
            ServiceMessageKind::LinkPathControl => Ok(Self::PathControl(
                AuthenticatedPathControlMessage::from_authenticated_service_message(
                    service_message,
                )?,
            )),
            ServiceMessageKind::LinkSessionInit => Ok(Self::SessionInit(
                AuthenticatedSessionInitMessage::from_authenticated_service_message(
                    service_message,
                )?,
            )),
            ServiceMessageKind::LinkSessionPathSwitch => Ok(Self::SessionPathSwitch(
                AuthenticatedSessionPathSwitchMessage::from_authenticated_service_message(
                    service_message,
                )?,
            )),
            unsupported => Err(LinkMessageError::UnsupportedServiceKind(unsupported)),
        }
    }
}

#[derive(Debug, Error)]
pub enum LinkMessageError {
    #[error(transparent)]
    ServiceMessage(#[from] ServiceMessageError),
    #[error("link message lower-level service kind `{0:?}` is not a supported link family")]
    UnsupportedServiceKind(ServiceMessageKind),
    #[error(transparent)]
    PathControl(#[from] PathControlError),
    #[error(transparent)]
    SessionInit(#[from] SessionInitError),
    #[error(transparent)]
    SessionPathSwitch(#[from] SessionPathSwitchError),
}
