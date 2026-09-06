/// Passphrase fallback implementation.
pub mod fallback;
/// OS and hardware keyring backend abstraction.
pub mod keyring_backend;
/// Linux TPM 2.0 hardware KEK integration.
pub mod linux_tpm;
/// macOS Secure Enclave hardware KEK integration.
pub mod macos_secure_enclave;

use crate::envfile::lockfile::KeyProviderType;
use zeroize::Zeroizing;

pub use keyring_backend::WrappedMasterKey;

/// Store the master key using either OS hardware enclave keyring or passphrase fallback.
pub fn store_key(
    project_id: &str,
    master_key: &[u8; 32],
    use_passphrase: bool,
    custom_passphrase: Option<&str>,
    salt: &[u8],
) -> Result<(KeyProviderType, Zeroizing<[u8; 32]>), String> {
    if use_passphrase {
        Ok((KeyProviderType::Passphrase, Zeroizing::new(*master_key)))
    } else {
        match keyring_backend::store_key(project_id, master_key) {
            Ok(_) => Ok((
                KeyProviderType::HardwareEnclave,
                Zeroizing::new(*master_key),
            )),
            Err(e) => {
                eprintln!(
                    "⚠️  Hardware enclave storage unavailable ({}). Falling back to passphrase protection...",
                    e
                );
                let pass = match custom_passphrase {
                    Some(p) => Zeroizing::new(p.to_string()),
                    None => fallback::prompt_or_get_passphrase(
                        "Enter a passphrase to lock project secrets",
                    )?,
                };
                let derived = fallback::derive_passphrase_key(&pass, salt)?;
                Ok((KeyProviderType::Passphrase, derived))
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
                    Err(format!(
                        "Hardware key not found in local OS enclave: {}. This lockfile was sealed with a machine-bound hardware key. To share projects across machines or CI/CD, seal with 'interenv lock --passphrase'.",
                        err
                    ))
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
