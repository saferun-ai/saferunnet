use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModuleError {
    #[error("module lifecycle violation: {0}")]
    Lifecycle(String),
}

pub trait RuntimeModule {
    fn name(&self) -> &'static str;
    fn start(&mut self) -> Result<(), ModuleError>;
    fn stop(&mut self) -> Result<(), ModuleError>;
}
