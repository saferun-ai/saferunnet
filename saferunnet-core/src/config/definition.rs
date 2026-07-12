use std::path::PathBuf;

/// Typed configuration value used in option definitions.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    Bool(bool),
    Int(i64),
    String(String),
    List(Vec<String>),
    Path(PathBuf),
}

/// Metadata for a single configuration option.
#[derive(Debug, Clone)]
pub struct OptionDef {
    pub section: &'static str,
    pub key: &'static str,
    pub default: ConfigValue,
    pub description: &'static str,
    pub required: bool,
}

/// Return the canonical set of option definitions for SaferunNet.
///
/// These map to the fields in [`super::NormalizedConfig`] and its sub-structs.
pub fn default_option_defs() -> Vec<OptionDef> {
    vec![
        // ── router ──
        OptionDef {
            section: "router",
            key: "nickname",
            default: ConfigValue::String("saferunnet".into()),
            description: "Human-readable node nickname.",
            required: false,
        },
        OptionDef {
            section: "router",
            key: "data_dir",
            default: ConfigValue::Path("./var/lib/saferunnet".into()),
            description: "Directory for keys, RCs, and persistent state.",
            required: false,
        },
        OptionDef {
            section: "router",
            key: "bind_port",
            default: ConfigValue::Int(1090),
            description: "UDP port for Lokinet traffic.",
            required: false,
        },
        OptionDef {
            section: "router",
            key: "rpc_port",
            default: ConfigValue::Int(1190),
            description: "TCP port for JSON-RPC admin API.",
            required: false,
        },
        // ── network ──
        OptionDef {
            section: "network",
            key: "exit",
            default: ConfigValue::Bool(false),
            description: "Operate as an exit node.",
            required: false,
        },
        OptionDef {
            section: "network",
            key: "reachable",
            default: ConfigValue::Bool(false),
            description: "Advertise as publicly reachable.",
            required: false,
        },
        OptionDef {
            section: "network",
            key: "hops",
            default: ConfigValue::Int(4),
            description: "Number of hops per path.",
            required: false,
        },
        OptionDef {
            section: "network",
            key: "paths",
            default: ConfigValue::Int(6),
            description: "Number of paths to maintain.",
            required: false,
        },
        // ── logging ──
        OptionDef {
            section: "logging",
            key: "level",
            default: ConfigValue::String("info".into()),
            description: "Log level: trace, debug, info, warn, error.",
            required: false,
        },
        // ── dns ──
        OptionDef {
            section: "dns",
            key: "upstream",
            default: ConfigValue::String("".into()),
            description: "Upstream DNS resolver (empty = system default).",
            required: false,
        },
        OptionDef {
            section: "dns",
            key: "bind_addr",
            default: ConfigValue::String("127.3.2.1:53".into()),
            description: "Local DNS server bind address.",
            required: false,
        },
        // ── api ──
        OptionDef {
            section: "api",
            key: "enabled",
            default: ConfigValue::Bool(true),
            description: "Enable the JSON-RPC admin API.",
            required: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_option_defs_count() {
        let defs = default_option_defs();
        assert!(defs.len() >= 12, "expected at least 12 definitions, got {}", defs.len());
    }

    #[test]
    fn test_option_defs_no_duplicate_keys() {
        let defs = default_option_defs();
        let mut seen = HashSet::new();
        for def in &defs {
            let key = format!("{}::{}", def.section, def.key);
            assert!(seen.insert(key.clone()), "duplicate option definition: {key}");
        }
    }
}

