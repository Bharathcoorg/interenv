use dialoguer::Password;
use std::env;
use zeroize::Zeroizing;

use crate::crypto::kdf::derive_key_from_passphrase;

/// Interactively prompts the user for a passphrase or reads it from the environment if CI is active.
pub fn prompt_or_get_passphrase(prompt_text: &str) -> Result<Zeroizing<String>, String> {
    if let Ok(val) = env::var("INTERENV_PASSPHRASE") {
        if !val.trim().is_empty() {
            if env::var("INTERENV_CI").is_ok_and(|v| v == "1") {
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

    Password::new()
        .with_prompt(prompt_text)
        .interact()
        .map(Zeroizing::new)
        .map_err(|e| format!("Password input error: {e}"))
}

/// Derives a 256-bit encryption key from a passphrase and salt using Argon2id.
pub fn derive_passphrase_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    derive_key_from_passphrase(passphrase, salt)
}
