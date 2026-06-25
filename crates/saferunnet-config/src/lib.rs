mod model;

pub use model::{LoggingConfig, NormalizedConfig, RouterConfig};

use std::path::Path;

use saferunnet_compat_lokinet::{ParseError, parse};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file `{path}`: {source}")]
    ReadConfig {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("missing required router section")]
    MissingRouterSection,
    #[error("invalid value for {field}: {reason}")]
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
}

pub fn load_from_str(input: &str) -> Result<NormalizedConfig, ConfigError> {
    let raw = parse(input)?;
    normalize(raw)
}

pub fn load_from_file(path: impl AsRef<Path>) -> Result<NormalizedConfig, ConfigError> {
    let path = path.as_ref();
    let input = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadConfig {
        path: path.display().to_string(),
        source,
    })?;
    load_from_str(&input)
}

fn normalize(
    raw: saferunnet_compat_lokinet::RawLokinetConfig,
) -> Result<NormalizedConfig, ConfigError> {
    let router = raw
        .sections
        .get("router")
        .ok_or(ConfigError::MissingRouterSection)?;

    let nickname = router
        .get("nickname")
        .cloned()
        .unwrap_or_else(|| "saferunnet-node".to_string());
    if nickname.trim().is_empty() {
        return Err(ConfigError::InvalidValue {
            field: "router.nickname",
            reason: "value cannot be blank",
        });
    }
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
