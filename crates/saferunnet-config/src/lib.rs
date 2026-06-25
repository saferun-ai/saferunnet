mod model;

pub use model::{LoggingConfig, NormalizedConfig, RouterConfig};

use saferunnet_compat_lokinet::{ParseError, parse};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("missing required router section")]
    MissingRouterSection,
}

pub fn load_from_str(input: &str) -> Result<NormalizedConfig, ConfigError> {
    let raw = parse(input)?;
    let router = raw
        .sections
        .get("router")
        .ok_or(ConfigError::MissingRouterSection)?;

    let nickname = router
        .get("nickname")
        .cloned()
        .unwrap_or_else(|| "saferunnet-node".to_string());
    let data_dir = router
        .get("data_dir")
        .cloned()
        .unwrap_or_else(|| "./var/lib/saferunnet".to_string());
    let level = raw
        .sections
        .get("logging")
        .and_then(|logging| logging.get("level"))
        .cloned()
        .unwrap_or_else(|| "info".to_string());

    Ok(NormalizedConfig {
        router: RouterConfig { nickname, data_dir },
        logging: LoggingConfig { level },
    })
}
