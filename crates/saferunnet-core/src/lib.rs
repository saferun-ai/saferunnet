mod lifecycle;
mod module;
mod service;

use std::sync::Arc;
pub type RuntimeHandle = Arc<tokio::runtime::Runtime>;

pub use lifecycle::LifecycleState;
pub use module::{ModuleError, RuntimeModule};
pub use service::{ServiceKey, ServiceRegistry};
