/// Shared message constants and helpers, ported from Lokinet C++ `llarp/messages/common.hpp`.
///
/// C++ equivalent: `llarp::messages::STATUS_KEY`, `serialize_status_response`,
/// and derived `TIMEOUT_RESPONSE` / `ERROR_RESPONSE` / `OK_RESPONSE`.
use std::sync::LazyLock;

/// Status key prefix used in bt-dict status responses.
/// C++: `inline constexpr auto STATUS_KEY = "!"sv;`
pub const STATUS_KEY: &str = "!";

/// Serialize a status response in `"!value"` format.
/// C++ uses `oxenc::bt_dict_producer` with `STATUS_KEY` → value;
/// Rust version emits the concatenated form for wire‑compatibility.
pub fn serialize_status_response(value: &str) -> String {
    format!("{}{}", STATUS_KEY, value)
}

macro_rules! status_response {
    ($name:ident, $value:literal) => {
        pub static $name: LazyLock<String> =
            LazyLock::new(|| serialize_status_response($value));
    };
}

status_response!(TIMEOUT_RESPONSE, "TIMEOUT");
status_response!(ERROR_RESPONSE, "ERROR");
status_response!(OK_RESPONSE, "OK");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_serialize_format() {
        let s = serialize_status_response("OK");
        assert_eq!(s, "!OK");
    }

    #[test]
    fn test_constants_exist() {
        assert_eq!(&*TIMEOUT_RESPONSE, "!TIMEOUT");
        assert_eq!(&*ERROR_RESPONSE, "!ERROR");
        assert_eq!(&*OK_RESPONSE, "!OK");
    }

    #[test]
    fn test_status_key_constant() {
        assert_eq!(STATUS_KEY, "!");
    }

    #[test]
    fn test_serialize_different_values() {
        assert_eq!(serialize_status_response("HELLO"), "!HELLO");
        assert_eq!(serialize_status_response("NOT FOUND"), "!NOT FOUND");
    }
}
