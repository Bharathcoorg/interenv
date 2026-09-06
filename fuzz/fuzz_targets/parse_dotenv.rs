#![no_main]
use interenv::envfile::parser::parse_dotenv;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_dotenv(s);
    }
});
