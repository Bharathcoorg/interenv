use std::collections::BTreeMap;
use std::fmt::Write;

/// Type alias representing parsed environment variable key-value pairs.
pub type EnvMap = BTreeMap<String, String>;

/// Validate if a string is a valid environment variable key: `^[A-Za-z_][A-Za-z0-9_]*$`
pub fn is_valid_env_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse a raw .env file string into key-value pairs.
/// Accurately tracks multiline quoted values across newlines, skips invalid keys,
/// strips trailing inline comments only when preceded by whitespace and unquoted.
pub fn parse_dotenv(content: &str) -> EnvMap {
    let mut map = EnvMap::new();

    let mut current_key: Option<String> = None;
    let mut current_val = String::new();
    let mut in_double_quotes = false;
    let mut in_single_quotes = false;
    let mut escaped = false;

    for line in content.lines() {
        // If currently in a multiline double-quote
        if in_double_quotes {
            current_val.push('\n');
            for ch in line.chars() {
                if escaped {
                    match ch {
                        'n' => current_val.push('\n'),
                        'r' => current_val.push('\r'),
                        't' => current_val.push('\t'),
                        '\\' => current_val.push('\\'),
                        '"' => current_val.push('"'),
                        other => {
                            current_val.push('\\');
                            current_val.push(other);
                        }
                    }
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_double_quotes = false;
                    break;
                } else {
                    current_val.push(ch);
                }
            }
            if !in_double_quotes {
                if let Some(k) = current_key.take() {
                    map.insert(k, current_val.clone());
                    current_val.clear();
                }
            }
            continue;
        }

        // If currently in a multiline single-quote
        if in_single_quotes {
            current_val.push('\n');
            for ch in line.chars() {
                if ch == '\'' {
                    in_single_quotes = false;
                    break;
                } else {
                    current_val.push(ch);
                }
            }
            if !in_single_quotes {
                if let Some(k) = current_key.take() {
                    map.insert(k, current_val.clone());
                    current_val.clear();
                }
            }
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let clean_line = if let Some(stripped) = trimmed.strip_prefix("export ") {
            stripped.trim_start()
        } else {
            trimmed
        };

        let Some((key_part, val_part)) = clean_line.split_once('=') else {
            continue;
        };

        let key = key_part.trim().to_string();
        if !is_valid_env_key(&key) {
            continue;
        }

        let raw_val = val_part.trim();

        if let Some(rest) = raw_val.strip_prefix('"') {
            // Double-quoted value
            let mut val = String::new();
            let mut closed = false;
            let mut is_esc = false;

            for ch in rest.chars() {
                if is_esc {
                    match ch {
                        'n' => val.push('\n'),
                        'r' => val.push('\r'),
                        't' => val.push('\t'),
                        '\\' => val.push('\\'),
                        '"' => val.push('"'),
                        other => {
                            val.push('\\');
                            val.push(other);
                        }
                    }
                    is_esc = false;
                } else if ch == '\\' {
                    is_esc = true;
                } else if ch == '"' {
                    closed = true;
                    break;
                } else {
                    val.push(ch);
                }
            }

            if closed {
                map.insert(key, val);
            } else {
                in_double_quotes = true;
                current_key = Some(key);
                current_val = val;
                escaped = is_esc;
            }
        } else if let Some(rest) = raw_val.strip_prefix('\'') {
            // Single-quoted value
            let mut val = String::new();
            let mut closed = false;

            for ch in rest.chars() {
                if ch == '\'' {
                    closed = true;
                    break;
                } else {
                    val.push(ch);
                }
            }

            if closed {
                map.insert(key, val);
            } else {
                in_single_quotes = true;
                current_key = Some(key);
                current_val = val;
            }
        } else {
            // Unquoted value: only strip trailing comment if preceded by whitespace
            let value_part = if let Some(idx) = raw_val.find(" #") {
                raw_val[..idx].trim_end()
            } else if let Some(idx) = raw_val.find("\t#") {
                raw_val[..idx].trim_end()
            } else {
                raw_val
            };
            map.insert(key, value_part.to_string());
        }
    }

    map
}

/// Format an EnvMap back to clean .env syntax.
pub fn format_dotenv(map: &EnvMap) -> String {
    let mut out = String::new();
    out.push_str("# Sealed by InterEnv - https://github.com/Bharathcoorg/interenv\n");
    for (k, v) in map {
        if v.contains('\n')
            || v.contains('\r')
            || v.contains('\t')
            || v.contains('\\')
            || v.contains(' ')
            || v.contains('"')
            || v.contains('\'')
        {
            let escaped = v
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\t', "\\t");
            let _ = writeln!(out, "{k}=\"{escaped}\"");
        } else {
            let _ = writeln!(out, "{k}={v}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_env_key() {
        assert!(is_valid_env_key("PORT"));
        assert!(is_valid_env_key("_PRIVATE_KEY"));
        assert!(is_valid_env_key("DATABASE_URL_2"));
        assert!(!is_valid_env_key("FOO.BAR"));
        assert!(!is_valid_env_key("2PORT"));
        assert!(!is_valid_env_key("FOO-BAR"));
        assert!(!is_valid_env_key("KEY WITH SPACE"));
        assert!(!is_valid_env_key(""));
    }

    #[test]
    fn test_multiline_parsing() {
        let content = r#"
RSA_KEY="-----BEGIN RSA PRIVATE KEY-----
Line 1
Line 2
-----END RSA PRIVATE KEY-----"
SIMPLE_KEY="hello world"
UNQUOTED=my_value # trailing comment
UNQUOTED_WITH_HASH=my#value
"#;
        let map = parse_dotenv(content);
        assert!(map.get("RSA_KEY").unwrap().contains("Line 1\nLine 2"));
        assert_eq!(map.get("SIMPLE_KEY").unwrap(), "hello world");
        assert_eq!(map.get("UNQUOTED").unwrap(), "my_value");
        assert_eq!(map.get("UNQUOTED_WITH_HASH").unwrap(), "my#value");
    }

    #[test]
    fn test_parse_dotenv_escaped_quotes_and_backslashes() {
        let input = "KEY=\"hello \\\\\\\"world\"\nBACKSLASH=\"backslash \\\\\"\n";
        let parsed = parse_dotenv(input);
        assert_eq!(parsed.get("KEY").unwrap(), "hello \\\"world");
        assert_eq!(parsed.get("BACKSLASH").unwrap(), "backslash \\");
    }

    #[test]
    fn test_parse_dotenv_env_file_variations() {
        let input = "DEV_ENV=val1\nMY_ENV=val2\n_ENV=val3\nENV=val4\n";
        let parsed = parse_dotenv(input);
        assert_eq!(parsed.get("DEV_ENV").unwrap(), "val1");
        assert_eq!(parsed.get("MY_ENV").unwrap(), "val2");
        assert_eq!(parsed.get("_ENV").unwrap(), "val3");
        assert_eq!(parsed.get("ENV").unwrap(), "val4");
    }

    #[test]
    fn test_format_dotenv_header() {
        let mut map = EnvMap::new();
        map.insert("FOO".to_string(), "bar".to_string());
        let formatted = format_dotenv(&map);
        assert!(formatted.contains("Sealed by InterEnv"));
    }
}
