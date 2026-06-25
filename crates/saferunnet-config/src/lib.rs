mod model;

pub use model::{LoggingConfig, NetworkConfig, NormalizedConfig, RouterConfig};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use saferunnet_compat_lokinet::{ParseError, RawLokinetConfig, parse};
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
    #[error("failed to read config directory `{path}`: {source}")]
    ReadConfigDir {
        path: String,
        #[source]
        source: std::io::Error,
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

pub fn load_from_path(path: impl AsRef<Path>) -> Result<NormalizedConfig, ConfigError> {
    let path = path.as_ref();
    let mut raw = parse_to_raw(path)?;

    for conf_d in overlay_dirs(path) {
        for file in sorted_ini_files(&conf_d)? {
            let next = parse_to_raw(&file)?;
            merge_raw_config(&mut raw, next);
        }
    }

    normalize(raw)
}

fn parse_to_raw(path: &Path) -> Result<RawLokinetConfig, ConfigError> {
    let input = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadConfig {
        path: path.display().to_string(),
        source,
    })?;
    parse(&input).map_err(ConfigError::from)
}

fn normalize(raw: RawLokinetConfig) -> Result<NormalizedConfig, ConfigError> {
    let router = raw
        .sections
        .get("router")
        .ok_or(ConfigError::MissingRouterSection)?;

    let nickname = last_value(router, "nickname").unwrap_or_else(|| "saferunnet-node".to_string());
    if nickname.trim().is_empty() {
        return Err(ConfigError::InvalidValue {
            field: "router.nickname",
            reason: "value cannot be blank",
        });
    }
    let data_dir =
        last_value(router, "data_dir").unwrap_or_else(|| "./var/lib/saferunnet".to_string());
    let level = raw
        .sections
        .get("logging")
        .and_then(|logging| last_value(logging, "level"))
        .unwrap_or_else(|| "info".to_string());
    let exit = parse_bool(raw.sections.get("network"), "exit")?;
    let reachable = parse_bool(raw.sections.get("network"), "reachable")?;
    let keyfile = raw
        .sections
        .get("network")
        .and_then(|network| last_value(network, "keyfile"));
    let ifaddr = raw
        .sections
        .get("network")
        .and_then(|network| last_value(network, "ifaddr"));
    let exit_nodes = raw
        .sections
        .get("network")
        .and_then(|network| network.get("exit-node"))
        .cloned()
        .unwrap_or_default();

    Ok(NormalizedConfig {
        router: RouterConfig { nickname, data_dir },
        logging: LoggingConfig { level },
        network: NetworkConfig {
            exit,
            reachable,
            keyfile,
            ifaddr,
            exit_nodes,
        },
    })
}

fn conf_d_path(path: &Path) -> PathBuf {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if !ext.is_empty() => path.with_extension(format!("{ext}.d")),
        _ => path.with_extension("d"),
    }
}

fn overlay_dirs(path: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let short = path.with_extension("d");
    if short.exists() {
        dirs.push(short);
    }

    let extended = conf_d_path(path);
    if extended.exists() && !dirs.contains(&extended) {
        dirs.push(extended);
    }

    dirs
}

fn sorted_ini_files(path: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(path).map_err(|source| ConfigError::ReadConfigDir {
        path: path.display().to_string(),
        source,
    })? {
        let entry = entry.map_err(|source| ConfigError::ReadConfigDir {
            path: path.display().to_string(),
            source,
        })?;
        let file_path = entry.path();
        if file_path.extension().and_then(|ext| ext.to_str()) == Some("ini") {
            files.push(file_path);
        }
    }
    files.sort();
    Ok(files)
}

fn merge_raw_config(base: &mut RawLokinetConfig, overlay: RawLokinetConfig) {
    for (section, values) in overlay.sections {
        let section_map = base.sections.entry(section).or_default();
        for (key, value) in values {
            section_map.entry(key).or_default().extend(value);
        }
    }
}

fn parse_bool(
    section: Option<&BTreeMap<String, Vec<String>>>,
    key: &'static str,
) -> Result<bool, ConfigError> {
    let Some(raw_value) = section.and_then(|section| last_value(section, key)) else {
        return Ok(false);
    };

    match raw_value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::InvalidValue {
            field: match key {
                "exit" => "network.exit",
                "reachable" => "network.reachable",
                _ => key,
            },
            reason: "expected a boolean value",
        }),
    }
}

fn last_value(section: &BTreeMap<String, Vec<String>>, key: &str) -> Option<String> {
    section.get(key).and_then(|values| values.last()).cloned()
}
