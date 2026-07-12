use serde_json::Value as JsonValue;

/// Typed parameter extraction from JSON-RPC request params.
///
/// Lokinet C++ equivalent: llarp/rpc/param_parser.hpp
pub struct ParamParser<'a> {
    params: &'a JsonValue,
}

impl<'a> ParamParser<'a> {
    pub fn new(params: &'a JsonValue) -> Self {
        Self { params }
    }

    /// Extract a required string parameter by name or position.
    pub fn required_string(&self, key: &str) -> Result<String, String> {
        self.get_value(key, |v| {
            v.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| format!("field '{}' must be a string", key))
        })
    }

    /// Extract an optional string parameter.
    pub fn optional_string(&self, key: &str) -> Option<String> {
        self.params.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    /// Extract an optional boolean parameter.
    pub fn optional_bool(&self, key: &str) -> Option<bool> {
        self.params.get(key).and_then(|v| v.as_bool())
    }

    /// Extract a required u64 parameter.
    pub fn required_u64(&self, key: &str) -> Result<u64, String> {
        self.get_value(key, |v| {
            v.as_u64()
                .ok_or_else(|| format!("field '{}' must be a number", key))
        })
    }

    /// Extract a required JSON object.
    pub fn required_object(&self) -> Result<&'a JsonValue, String> {
        if self.params.is_object() {
            Ok(self.params)
        } else {
            Err("params must be a JSON object".into())
        }
    }

    fn get_value<T, F: FnOnce(&JsonValue) -> Result<T, String>>(
        &self,
        key: &str,
        f: F,
    ) -> Result<T, String> {
        let field = self.params.get(key).ok_or_else(|| {
            format!("missing required field '{}'", key)
        })?;
        f(field)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_required_string() {
        let json: JsonValue = serde_json::json!({"name": "test-node"});
        let parser = ParamParser::new(&json);
        assert_eq!(parser.required_string("name").unwrap(), "test-node");
    }

    #[test]
    fn test_missing_required() {
        let json: JsonValue = serde_json::json!({"other": 1});
        let parser = ParamParser::new(&json);
        assert!(parser.required_string("name").is_err());
    }

    #[test]
    fn test_optional_bool() {
        let json: JsonValue = serde_json::json!({"exit": true});
        let parser = ParamParser::new(&json);
        assert_eq!(parser.optional_bool("exit"), Some(true));
        assert_eq!(parser.optional_bool("nonexist"), None);
    }

    #[test]
    fn test_required_u64() {
        let json: JsonValue = serde_json::json!({"session_id": 42});
        let parser = ParamParser::new(&json);
        assert_eq!(parser.required_u64("session_id").unwrap(), 42);
    }
}
