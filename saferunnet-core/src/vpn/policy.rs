use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExitPolicyError {
    #[error("exit traffic not allowed to {target}:{port}")]
    Denied { target: String, port: u16 },
}

pub trait ExitPolicy {
    fn allows(&self, target: &str, port: u16) -> Result<(), ExitPolicyError>;
}

#[derive(Debug, Default, Clone)]
pub struct PermitAllPolicy;

impl ExitPolicy for PermitAllPolicy {
    fn allows(&self, _target: &str, _port: u16) -> Result<(), ExitPolicyError> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AllowListPolicy {
    allowed: Vec<(String, u16)>,
}

impl AllowListPolicy {
    pub fn new(allowed: Vec<(String, u16)>) -> Self {
        Self { allowed }
    }
}

impl ExitPolicy for AllowListPolicy {
    fn allows(&self, target: &str, port: u16) -> Result<(), ExitPolicyError> {
        if self.allowed.iter().any(|(t, p)| t == target && *p == port) {
            Ok(())
        } else {
            Err(ExitPolicyError::Denied {
                target: target.to_string(),
                port,
            })
        }
    }
}
