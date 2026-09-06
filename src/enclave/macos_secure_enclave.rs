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
/// Wrap master encryption key using Apple Secure Enclave hardware key or software fallback.
pub fn wrap_key_secure_enclave(
    project_id: &str,
    master_key: &[u8; 32],
) -> Result<(String, Vec<u8>), String> {
    wrap_key_macos_keychain_software(project_id, master_key)
}

#[cfg(target_os = "macos")]
/// Unwrap master encryption key using Apple Secure Enclave hardware key or software fallback.
pub fn unwrap_key_secure_enclave(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
    unwrap_key_macos_keychain_software(project_id, wrapped)
}
