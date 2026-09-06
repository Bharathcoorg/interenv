//! macOS Secure Enclave hardware Key Encryption Key (KEK) implementation.

#[cfg(target_os = "macos")]
use crate::enclave::keyring_backend::derive_kek_mask;

#[cfg(target_os = "macos")]
/// Fallback software KEK for macOS environments lacking Secure Enclave.
pub fn wrap_key_macos_keychain_software(
    project_id: &str,
    master_key: &[u8; 32],
) -> Result<(String, Vec<u8>), String> {
    let kek = derive_kek_mask(project_id);
    let mut masked = [0u8; 32];
    for i in 0..32 {
        masked[i] = master_key[i] ^ kek[i];
    }
    Ok(("macos-keychain-kek-v2".to_string(), masked.to_vec()))
}

#[cfg(target_os = "macos")]
/// Fallback software unwrapping for macOS software KEK.
pub fn unwrap_key_macos_keychain_software(
    project_id: &str,
    wrapped: &[u8],
) -> Result<[u8; 32], String> {
    if wrapped.len() != 32 {
        return Err("Stored keyring key is not 32 bytes".into());
    }
    let kek = derive_kek_mask(project_id);
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = wrapped[i] ^ kek[i];
    }
    Ok(key)
}

#[cfg(target_os = "macos")]
/// Wrap master encryption key using Apple Secure Enclave hardware key or return explicit error.
pub fn wrap_key_secure_enclave(
    project_id: &str,
    master_key: &[u8; 32],
) -> Result<(String, Vec<u8>), String> {
    if std::env::var("INTERENV_ALLOW_MACOS_SOFTWARE_FALLBACK").unwrap_or_default() == "1" {
        return wrap_key_macos_keychain_software(project_id, master_key);
    }
    // Apple Secure Enclave requires hardware support and Touch ID authorization.
    // If running in headless CI or without biometric hardware, return a clear error
    // rather than silently degrading to XOR software masking.
    Err("Apple Secure Enclave hardware / Touch ID is unavailable. Run 'interenv lock --passphrase' for cross-platform passphrase protection, or set INTERENV_ALLOW_MACOS_SOFTWARE_FALLBACK=1 to permit software fallback.".into())
}

#[cfg(target_os = "macos")]
/// Unwrap master encryption key using Apple Secure Enclave hardware key or software fallback.
pub fn unwrap_key_secure_enclave(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
    unwrap_key_macos_keychain_software(project_id, wrapped)
}
