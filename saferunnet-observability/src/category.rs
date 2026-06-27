use std::collections::HashMap;
use std::sync::RwLock;
use tracing::Level;

/// Maps module categories to log levels.
/// Lokinet C++ equivalent: log::apply_categories()
pub struct CategoryFilter {
    levels: RwLock<HashMap<String, Level>>,
}

impl CategoryFilter {
    pub fn new(config: &HashMap<String, String>) -> Self {
        let levels = config
            .iter()
            .filter_map(|(cat, level_str)| {
                let level = match level_str.to_lowercase().as_str() {
                    "trace" => Level::TRACE,
                    "debug" => Level::DEBUG,
                    "info" => Level::INFO,
                    "warn" => Level::WARN,
                    "error" => Level::ERROR,
                    _ => return None,
                };
                Some((cat.clone(), level))
            })
            .collect();
        Self {
            levels: RwLock::new(levels),
        }
    }

    /// Get the configured level for a category, or the default
    pub fn level_for(&self, category: &str, default: Level) -> Level {
        self.levels
            .read()
            .unwrap()
            .get(category)
            .copied()
            .unwrap_or(default)
    }

    /// Update a single category level at runtime
    pub fn set_level(&self, category: &str, level: Level) {
        self.levels.write().unwrap().insert(category.into(), level);
    }

    /// Check if a given level is enabled for a category
    pub fn is_enabled(&self, category: &str, level: Level, default: Level) -> bool {
        level <= self.level_for(category, default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_category_filter_default() {
        let config = HashMap::new();
        let filter = CategoryFilter::new(&config);
        assert_eq!(filter.level_for("router", Level::INFO), Level::INFO);
    }

    #[test]
    fn test_category_filter_custom() {
        let config = HashMap::from([("router".into(), "debug".into())]);
        let filter = CategoryFilter::new(&config);
        assert_eq!(filter.level_for("router", Level::INFO), Level::DEBUG);
        assert_eq!(filter.level_for("unknown", Level::WARN), Level::WARN);
    }

    #[test]
    fn test_category_is_enabled() {
        let config = HashMap::from([("router".into(), "warn".into())]);
        let filter = CategoryFilter::new(&config);
        assert!(!filter.is_enabled("router", Level::INFO, Level::INFO));
        assert!(filter.is_enabled("router", Level::ERROR, Level::INFO));
        assert!(filter.is_enabled("unknown", Level::INFO, Level::INFO));
    }
}
