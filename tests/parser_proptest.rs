use interenv::envfile::parser::{format_dotenv, parse_dotenv};
use proptest::prelude::*;

proptest! {
    #[test]
    fn parser_never_panics(s in ".*") {
        let _ = parse_dotenv(&s);
    }

    #[test]
    fn round_trip_idempotent(
        k in "[A-Za-z_][A-Za-z0-9_]{0,20}",
        v in "[A-Za-z0-9_ =:;/?.!-]{0,50}"
    ) {
        let input = format!("{}=\"{}\"\n", k, v);
        let parsed = parse_dotenv(&input);
        if !k.is_empty() {
            prop_assert_eq!(parsed.get(&k), Some(&v));
            let reformatted = format_dotenv(&parsed);
            let re_parsed = parse_dotenv(&reformatted);
            prop_assert_eq!(parsed, re_parsed);
        }
    }
}

#[test]
fn test_multiline_pem_roundtrip() {
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0r1Z\n3v5w9Xy...\n-----END RSA PRIVATE KEY-----";
    let input = format!(
        "PRIVATE_KEY=\"{}\"\nANOTHER_KEY=\"simple\"\n",
        pem.replace('\n', "\\n")
    );
    let parsed = parse_dotenv(&input);

    assert_eq!(parsed.get("PRIVATE_KEY").unwrap(), pem);
    assert_eq!(parsed.get("ANOTHER_KEY").unwrap(), "simple");

    let reformatted = format_dotenv(&parsed);
    let re_parsed = parse_dotenv(&reformatted);
    assert_eq!(parsed, re_parsed);
}
