use std::env;
use dialoguer::Password;
use zeroize::Zeroizing;

use crate::crypto::kdf::derive_key_from_passphrase;

pub fn prompt_or_get_passphrase(prompt_text: &str) -> Result<String, String> {
    // 1. Check if provided via environment variable (ideal for CI/CD, Docker, scripts)
    if let Ok(val) = env::var("INTERENV_PASSPHRASE") {
        if !val.trim().is_empty() {
            return Ok(val);
        }
    }

    // 2. Interactive terminal prompt with no-echo
    Password::new()
        .with_prompt(prompt_text)
        .interact()
        .map_err(|e| format!("Password input error: {}", e))
}

pub fn derive_passphrase_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    derive_key_from_passphrase(passphrase, salt)
}
