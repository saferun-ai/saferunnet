use std::collections::BTreeMap;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLokinetConfig {
    pub sections: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("line {line}: key-value pair appears before any section")]
    MissingSection { line: usize },
    #[error("line {line}: invalid entry `{content}`")]
    InvalidEntry { line: usize, content: String },
}


/// Strip surrounding single or double quotes from a value string.
pub fn parse_quoted(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 {
        let first = s.as_bytes()[0];
        let last = s.as_bytes()[s.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

/// Split a comma-separated string into trimmed tokens, filtering empties.
pub fn parse_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Generate a default .ini file string from the canonical option definitions.
///
/// Requires `definition::default_option_defs` to be in scope (caller must pass it in
/// or the function can be called from `mod.rs` where the definition module is visible).
pub fn generate_default_ini(defs: &[crate::config::definition::OptionDef]) -> String {
    use std::collections::BTreeMap;

    let mut sections: BTreeMap<&str, Vec<&crate::config::definition::OptionDef>> = BTreeMap::new();
    for def in defs {
        sections.entry(def.section).or_default().push(def);
    }

    let mut out = String::new();
    // Collect sections in stable order
    let mut section_names: Vec<&str> = sections.keys().copied().collect();
    section_names.sort();

    for section in section_names {
        out.push_str(&format!("# {section} settings\n"));
        out.push_str(&format!("[{section}]\n"));
        for def in &sections[section] {
            let val_str = match &def.default {
                crate::config::definition::ConfigValue::Bool(b) => b.to_string(),
                crate::config::definition::ConfigValue::Int(i) => i.to_string(),
                crate::config::definition::ConfigValue::String(s) => s.clone(),
                crate::config::definition::ConfigValue::List(v) => v.join(", "),
                crate::config::definition::ConfigValue::Path(p) => p.display().to_string(),
            };
            if !def.description.is_empty() {
                out.push_str(&format!("# {}\n", def.description));
            }
            out.push_str(&format!("{}={val_str}\n", def.key));
        }
        out.push('\n');
    }

    out
}
pub fn parse(input: &str) -> Result<RawLokinetConfig, ParseError> {
    let mut sections = BTreeMap::new();
    let mut current_section: Option<String> = None;

    for (index, raw_line) in input.lines().enumerate() {
        let line_no = index + 1;
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let name = line
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .to_string();
            sections.entry(name.clone()).or_insert_with(BTreeMap::new);
            current_section = Some(name);
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(ParseError::InvalidEntry {
                line: line_no,
                content: line.to_string(),
            });
        };

        let Some(section_name) = current_section.clone() else {
            return Err(ParseError::MissingSection { line: line_no });
        };

        sections
            .entry(section_name)
            .or_insert_with(BTreeMap::new)
            .entry(key.trim().to_string())
            .or_insert_with(Vec::new)
            .push(value.trim().to_string());
    }

    Ok(RawLokinetConfig { sections })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_ini() {
        let input = "[router]\nnickname=test\nbind_port=1234\n";
        let cfg = parse(input).unwrap();
        assert_eq!(cfg.sections["router"]["nickname"][0], "test");
        assert_eq!(cfg.sections["router"]["bind_port"][0], "1234");
    }

    #[test]
    fn test_parse_multiple_sections() {
        let input = "[router]\nnickname=a\n\n[network]\nexit=true\n";
        let cfg = parse(input).unwrap();
        assert!(cfg.sections.contains_key("router"));
        assert!(cfg.sections.contains_key("network"));
    }

    #[test]
    fn test_parse_comments_ignored() {
        let input = "# comment\n; also comment\n[router]\nnickname=test\n";
        let cfg = parse(input).unwrap();
        assert_eq!(cfg.sections["router"]["nickname"][0], "test");
    }

    #[test]
    fn test_parse_empty_input() {
        let cfg = parse("").unwrap();
        assert!(cfg.sections.is_empty());
    }

    #[test]
    fn test_parse_error_no_section() {
        let result = parse("key=value");
        assert!(result.is_err());
    }

    #[test]

    #[test]
    fn test_generate_default_ini() {
        let defs = crate::config::definition::default_option_defs();
        let ini = generate_default_ini(&defs);
        assert!(ini.contains("[router]"));
        assert!(ini.contains("nickname=saferunnet"));
        assert!(ini.contains("bind_port=1090"));
        assert!(ini.contains("[network]"));
        assert!(ini.contains("hops=4"));
        assert!(ini.contains("[logging]"));
        assert!(ini.contains("level=info"));
        assert!(ini.contains("[dns]"));
        assert!(ini.contains("[api]"));
    }

    #[test]
    fn test_parse_quoted_double() {
        assert_eq!(parse_quoted("\"hello\""), "hello");
        assert_eq!(parse_quoted("'world'"), "world");
    }

    #[test]
    fn test_parse_quoted_unquoted() {
        assert_eq!(parse_quoted("plain"), "plain");
    }

    #[test]
    fn test_parse_list_simple() {
        let result = parse_list("a, b, c");
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_parse_list_empty() {
        let result = parse_list("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_list_single() {
        let result = parse_list("only");
        assert_eq!(result, vec!["only"]);
    }
    fn test_parse_multiple_values_same_key() {
        let input = "[router]\nbootstrap=a.com\nbootstrap=b.com\n";
        let cfg = parse(input).unwrap();
        let values = &cfg.sections["router"]["bootstrap"];
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], "a.com");
        assert_eq!(values[1], "b.com");
    }
}

