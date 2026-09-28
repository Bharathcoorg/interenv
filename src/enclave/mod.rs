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
            Ok(stored) => {
                let provider = if stored.kek_id.starts_with("linux-tpm")
                    || stored.kek_id.starts_with("windows-ncrypt")
                    || stored.kek_id.starts_with("macos-secure-enclave")
                {
                    KeyProviderType::HardwareEnclave
                } else if stored.kek_id.starts_with("windows-dpapi") {
                    KeyProviderType::WindowsDpapi
                } else {
                    KeyProviderType::OsKeyring
                };
                Ok((provider, Zeroizing::new(*master_key)))
            }
            Err(hardware_error) => {
                eprintln!(
                    "ℹ️  Hardware-backed key storage unavailable ({hardware_error}); using the OS credential store without claiming hardware protection."
                );
                let _stored = keyring_backend::store_key_os_keyring(project_id, master_key)?;
                Ok((KeyProviderType::OsKeyring, Zeroizing::new(*master_key)))
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
        KeyProviderType::HardwareEnclave | KeyProviderType::OsKeyring => {
            match keyring_backend::retrieve_key(project_id) {
                Ok(k) => Ok(k),
                Err(err) => {
                    let guidance = match provider {
                        KeyProviderType::HardwareEnclave => "machine-bound hardware key storage",
                        KeyProviderType::OsKeyring => "local operating-system credential storage",
                        KeyProviderType::WindowsDpapi => "Windows DPAPI credential protection",
                        KeyProviderType::Passphrase => "passphrase protection",
                    };
                    Err(format!(
                        "Protected key unavailable from {guidance}: {err}. To share projects across machines or CI/CD, seal with 'interenv lock --passphrase'."
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
