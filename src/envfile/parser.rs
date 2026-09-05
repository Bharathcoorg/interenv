use std::collections::BTreeMap;

pub type EnvMap = BTreeMap<String, String>;

/// Parse a raw .env file string into key-value pairs.
/// Supports comments (#), exports (export KEY=VAL), quoted values ("...", '...'), and escaped characters.
pub fn parse_dotenv(content: &str) -> EnvMap {
    let mut map = EnvMap::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip empty lines and comment lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Strip leading "export " if present
        let clean_line = if let Some(stripped) = trimmed.strip_prefix("export ") {
            stripped.trim_start()
        } else {
            trimmed
        };

        // Find the first '=' delimiter
        if let Some((key_part, val_part)) = clean_line.split_once('=') {
            let key = key_part.trim().to_string();
            if key.is_empty() {
                continue;
            }

            let val = parse_value(val_part.trim());
            map.insert(key, val);
        }
    }

    map
}

/// Format an EnvMap back to clean .env syntax.
pub fn format_dotenv(map: &EnvMap) -> String {
    let mut out = String::new();
    out.push_str("# Sealed by ghostenv - https://github.com/Bharathcoorg/ghostenv\n");
    for (k, v) in map {
        if v.contains('\n') || v.contains(' ') || v.contains('"') || v.contains('\'') {
            let escaped = v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
            out.push_str(&format!("{}=\"{}\"\n", k, escaped));
        } else {
            out.push_str(&format!("{}={}\n", k, v));
        }
    }
    out
}

fn parse_value(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }

    // Check if double-quoted
    if raw.starts_with('"') {
        if let Some(end_idx) = find_closing_quote(raw, '"') {
            let inner = &raw[1..end_idx];
            return unescape_double_quoted(inner);
        }
    }

    // Check if single-quoted (literal)
    if raw.starts_with('\'') {
        if let Some(end_idx) = find_closing_quote(raw, '\'') {
            return raw[1..end_idx].to_string();
        }
    }

    // Unquoted: strip any trailing inline comments (e.g. `KEY=value # comment`)
    let value_part = if let Some((val, _)) = raw.split_once(" #") {
        val.trim_end()
    } else {
        raw
    };

    value_part.to_string()
}

fn find_closing_quote(s: &str, quote_char: char) -> Option<usize> {
    let mut chars = s.char_indices().skip(1);
    let mut escaped = false;

    while let Some((idx, ch)) = chars.next() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quote_char == '"' {
            escaped = true;
            continue;
        }
        if ch == quote_char {
            return Some(idx);
        }
    }
    None
}

fn unescape_double_quoted(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dotenv() {
        let content = r#"
# Sample config
export OPENAI_API_KEY="sk-123456789"
PORT=8080 # default port
DATABASE_URL='postgres://user:pass@localhost:5432/db?ssl=true'
MULTI_LINE="hello\nworld"
EMPTY=
"#;
        let map = parse_dotenv(content);
        assert_eq!(map.get("OPENAI_API_KEY").unwrap(), "sk-123456789");
        assert_eq!(map.get("PORT").unwrap(), "8080");
        assert_eq!(map.get("DATABASE_URL").unwrap(), "postgres://user:pass@localhost:5432/db?ssl=true");
        assert_eq!(map.get("MULTI_LINE").unwrap(), "hello\nworld");
        assert_eq!(map.get("EMPTY").unwrap(), "");
    }
}
