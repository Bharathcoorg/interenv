use dialoguer::Password;
use std::env;
use zeroize::Zeroizing;

use crate::crypto::kdf::derive_key_from_passphrase;

pub fn prompt_or_get_passphrase(prompt_text: &str) -> Result<Zeroizing<String>, String> {
    // 1. Check if provided via environment variable, but ONLY if INTERENV_CI=1 is set
    if let Ok(val) = env::var("INTERENV_PASSPHRASE") {
        if !val.trim().is_empty() {
            if env::var("INTERENV_CI").map(|v| v == "1").unwrap_or(false) {
                eprintln!(
                    "⚠️  Using INTERENV_PASSPHRASE from environment (INTERENV_CI is enabled)"
                );
                return Ok(Zeroizing::new(val));
            } else {
                eprintln!(
                    "⚠️  INTERENV_PASSPHRASE is set, but ignored because INTERENV_CI=1 is not set. Use interactive prompt or set INTERENV_CI=1."
                );
            }
        }
    }

    // 2. Interactive terminal prompt with no-echo
    Password::new()
        .with_prompt(prompt_text)
        .interact()
        .map(Zeroizing::new)
        .map_err(|e| format!("Password input error: {}", e))
}

pub fn derive_passphrase_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    derive_key_from_passphrase(passphrase, salt)
}
