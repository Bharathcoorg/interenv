#![no_main]
use interenv::crypto::kdf::derive_key_from_passphrase;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let salt = [0u8; 16];
    if let Ok(pass) = std::str::from_utf8(data) {
        let _ = derive_key_from_passphrase(pass, &salt);
    }
});
