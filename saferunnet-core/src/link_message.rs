use thiserror::Error;

use crate::dht::dht_intro::{AuthenticatedDhtIntroMessage, DhtIntroError};
use crate::path::path_control::{AuthenticatedPathControlMessage, PathControlError};
use crate::path::svc_path_build::{
    AuthenticatedPathBuildMessage, AuthenticatedPathBuildResponse, PathBuildError,
};
use crate::path::transit_hop::{AuthenticatedTransitHopMessage, TransitHopError};
use crate::session::{
    AuthenticatedServiceMessage, AuthenticatedSessionAcceptMessage,
    AuthenticatedSessionCloseMessage, AuthenticatedSessionInitMessage,
    AuthenticatedSessionPathSwitchMessage, ServiceMessageError, ServiceMessageKind,
    SessionAcceptError, SessionCloseError, SessionInitError, SessionPathSwitchError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatedLinkMessage {
    PathControl(AuthenticatedPathControlMessage),
    SessionInit(AuthenticatedSessionInitMessage),
    SessionAccept(AuthenticatedSessionAcceptMessage),
    SessionPathSwitch(AuthenticatedSessionPathSwitchMessage),
    SessionClose(AuthenticatedSessionCloseMessage),
    DhtIntro(AuthenticatedDhtIntroMessage),
    PathBuild(AuthenticatedPathBuildMessage),
    PathBuildResponse(AuthenticatedPathBuildResponse),
    TransitHop(AuthenticatedTransitHopMessage),
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
            Self::PathControl(m) => m.service_message(),
            Self::SessionInit(m) => m.service_message(),
            Self::SessionAccept(m) => m.service_message(),
            Self::SessionPathSwitch(m) => m.service_message(),
            Self::SessionClose(m) => m.service_message(),
            Self::DhtIntro(m) => m.service_message(),
            Self::PathBuild(m) => m.service_message(),
            Self::PathBuildResponse(m) => m.service_message(),
            Self::TransitHop(m) => m.service_message(),
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
            ServiceMessageKind::LinkSessionAccept => Ok(Self::SessionAccept(
                AuthenticatedSessionAcceptMessage::from_authenticated_service_message(
                    service_message,
                )?,
            )),
            ServiceMessageKind::LinkSessionPathSwitch => Ok(Self::SessionPathSwitch(
                AuthenticatedSessionPathSwitchMessage::from_authenticated_service_message(
                    service_message,
                )?,
            )),
            ServiceMessageKind::LinkSessionClose => Ok(Self::SessionClose(
                AuthenticatedSessionCloseMessage::from_authenticated_service_message(
                    service_message,
                )?,
            )),
            ServiceMessageKind::DhtIntro => Ok(Self::DhtIntro(
                AuthenticatedDhtIntroMessage::from_authenticated_service_message(service_message)?,
            )),
            ServiceMessageKind::LinkPathBuild => Ok(Self::PathBuild(
                AuthenticatedPathBuildMessage::from_authenticated_service_message(service_message)?,
            )),
            ServiceMessageKind::LinkPathBuildResponse => Ok(Self::PathBuildResponse(
                AuthenticatedPathBuildResponse::from_authenticated_service_message(
                    service_message,
                )?,
            )),
            ServiceMessageKind::LinkTransitHop => Ok(Self::TransitHop(
                AuthenticatedTransitHopMessage::from_authenticated_service_message(
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
    SessionAccept(#[from] SessionAcceptError),
    #[error(transparent)]
    SessionPathSwitch(#[from] SessionPathSwitchError),
    #[error(transparent)]
    SessionClose(#[from] SessionCloseError),
    #[error(transparent)]
    DhtIntro(#[from] DhtIntroError),
    #[error(transparent)]
    PathBuild(#[from] PathBuildError),
    #[error(transparent)]
    TransitHop(#[from] TransitHopError),
}
