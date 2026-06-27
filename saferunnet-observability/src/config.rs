use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Log output type.
/// Lokinet C++ equivalent: log::Type enum (Print, File, System)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogType {
    Print,
    File,
    System,
}

/// Per-module log level configuration.
/// Lokinet C++ equivalent: llarp/config/config.hpp LoggingConfig
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(rename = "type")]
    pub log_type: Option<LogType>,

    /// File path for File type, or "stdout"/"-" for print
    pub file: Option<String>,

    /// Category → log level mapping (e.g., "router" → "debug")
    #[serde(default)]
    pub levels: HashMap<String, String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_type: Some(LogType::Print),
            file: None,
            levels: HashMap::from([
                ("router".into(), "info".into()),
                ("crypto".into(), "warn".into()),
                ("transport".into(), "info".into()),
                ("dns".into(), "info".into()),
                ("path".into(), "debug".into()),
                ("session".into(), "info".into()),
            ]),
        }
    }
}
