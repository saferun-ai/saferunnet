use std::sync::Once;

use thiserror::Error;
use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

#[derive(Debug, Error)]
pub enum ObservabilityError {
    #[error("failed to build log filter: {0}")]
    Filter(String),
}

pub fn install(filter: &str) -> Result<(), ObservabilityError> {
    let filter = EnvFilter::try_new(filter)
        .map_err(|error| ObservabilityError::Filter(error.to_string()))?;

    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .try_init();
    });

    Ok(())
}
