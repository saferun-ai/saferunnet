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
