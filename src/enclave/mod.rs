pub mod fallback;
pub mod keyring_backend;

use crate::envfile::lockfile::KeyProviderType;
use zeroize::Zeroizing;

/// Store the master key using either OS hardware enclave keyring or passphrase fallback.
pub fn store_key(
    project_id: &str,
    master_key: &[u8; 32],
    use_passphrase: bool,
    custom_passphrase: Option<&str>,
    salt: &[u8],
) -> Result<KeyProviderType, String> {
    if use_passphrase {
        // In passphrase mode, the key is already derived from passphrase + salt;
        // nothing is stored in keyring!
        Ok(KeyProviderType::Passphrase)
    } else {
        // Attempt hardware enclave store
        match keyring_backend::store_key(project_id, master_key) {
            Ok(_) => Ok(KeyProviderType::HardwareEnclave),
            Err(e) => {
                // If hardware store fails (e.g. headless linux container), prompt fallback
                eprintln!("⚠️  Hardware enclave storage unavailable ({}). Falling back to passphrase protection...", e);
                let pass = match custom_passphrase {
                    Some(p) => p.to_string(),
                    None => fallback::prompt_or_get_passphrase(
                        "Enter a passphrase to lock project secrets",
                    )?,
                };
                let _ = fallback::derive_passphrase_key(&pass, salt)?;
                Ok(KeyProviderType::Passphrase)
            }
        }
    }
}

/// Retrieve the master key depending on how the project was locked.
pub fn retrieve_key(
    project_id: &str,
    provider: KeyProviderType,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, String> {
    match provider {
        KeyProviderType::HardwareEnclave => {
            match keyring_backend::retrieve_key(project_id) {
                Ok(k) => Ok(k),
                Err(err) => {
                    // Offer fallback prompt if key is missing in local enclave (e.g. cloned repo on another machine)
                    eprintln!("⚠️  Hardware key not found in local enclave: {}.", err);
                    eprintln!("💡 If this repo was cloned from another machine, enter the unlock passphrase:");
                    let pass = fallback::prompt_or_get_passphrase("Project unlock passphrase")?;
                    fallback::derive_passphrase_key(&pass, salt)
                }
            }
        }
        KeyProviderType::Passphrase => {
            let pass =
                fallback::prompt_or_get_passphrase("Enter project passphrase to unlock secrets")?;
            fallback::derive_passphrase_key(&pass, salt)
        }
    }
}
