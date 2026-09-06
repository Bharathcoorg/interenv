//! macOS Secure Enclave hardware Key Encryption Key (KEK) implementation.

#[cfg(target_os = "macos")]
use crate::enclave::keyring_backend::{derive_kek_mask, derive_kek_with_salt};
#[cfg(target_os = "macos")]
use rand::rngs::OsRng;
#[cfg(target_os = "macos")]
use rand::RngCore;

#[cfg(target_os = "macos")]
/// Fallback software KEK for macOS environments lacking Secure Enclave.
pub fn wrap_key_macos_keychain_software(
    project_id: &str,
    master_key: &[u8; 32],
) -> Result<(String, Vec<u8>), String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let kek = derive_kek_with_salt(&salt, project_id);
    let mut combined = Vec::with_capacity(48);
    combined.extend_from_slice(&salt);
    for i in 0..32 {
        combined.push(master_key[i] ^ kek[i]);
    }
    Ok(("macos-keychain-kek-v3".to_string(), combined))
}

#[cfg(target_os = "macos")]
/// Fallback software unwrapping for macOS software KEK (supporting v3 salted and v2 legacy).
pub fn unwrap_key_macos_keychain_software(
    project_id: &str,
    wrapped: &[u8],
) -> Result<[u8; 32], String> {
    if wrapped.len() == 48 {
        let salt = &wrapped[..16];
        let masked = &wrapped[16..48];
        let kek = derive_kek_with_salt(salt, project_id);
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = masked[i] ^ kek[i];
        }
        Ok(key)
    } else if wrapped.len() == 32 {
        let kek = derive_kek_mask(project_id);
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = wrapped[i] ^ kek[i];
        }
        Ok(key)
    } else {
        Err("Stored keyring key is not 48 bytes (v3) or 32 bytes (legacy v2)".into())
    }
}

#[cfg(target_os = "macos")]
/// Wrap master encryption key using Apple Secure Enclave hardware key or software fallback.
pub fn wrap_key_secure_enclave(
    project_id: &str,
    master_key: &[u8; 32],
) -> Result<(String, Vec<u8>), String> {
    if std::env::var("INTERENV_ALLOW_MACOS_SOFTWARE_FALLBACK").unwrap_or_default() == "1" {
        return wrap_key_macos_keychain_software(project_id, master_key);
    }

    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

    let key_label = format!("interenv-se-{}", project_id);

    #[allow(deprecated)]
    let options = GenerateKeyOptions {
        key_type: Some(KeyType::ec()),
        size_in_bits: Some(256),
        label: Some(key_label),
        token: Some(Token::SecureEnclave),
        location: None,
        access_control: None,
    };

    let key = SecKey::new(&options).map_err(|e| {
        format!(
            "Apple Secure Enclave hardware key generation failed ({e}). Ensure Touch ID is enabled, run 'interenv lock --passphrase', or set INTERENV_ALLOW_MACOS_SOFTWARE_FALLBACK=1 for software fallback."
        )
    })?;

    let public_key = key
        .public_key()
        .ok_or_else(|| "Failed to extract public key from Secure Enclave key".to_string())?;

    let encrypted = public_key
        .encrypt_data(
            Algorithm::ECIESEncryptionStandardX963SHA256AESGCM,
            master_key,
        )
        .map_err(|e| format!("Secure Enclave ECIES encryption failed: {e}"))?;

    Ok(("macos-secure-enclave-v1".to_string(), encrypted))
}

#[cfg(target_os = "macos")]
/// Unwrap master encryption key using Apple Secure Enclave hardware key or software fallback.
pub fn unwrap_key_secure_enclave(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
    if std::env::var("INTERENV_ALLOW_MACOS_SOFTWARE_FALLBACK").unwrap_or_default() == "1" {
        return unwrap_key_macos_keychain_software(project_id, wrapped);
    }

    use security_framework::item::{ItemClass, ItemSearchOptions, Reference, SearchResult};
    use security_framework::key::Algorithm;

    let key_label = format!("interenv-se-{}", project_id);

    let mut search_opts = ItemSearchOptions::new();
    search_opts
        .class(ItemClass::key())
        .label(&key_label)
        .load_refs(true);

    let search = search_opts
        .search()
        .map_err(|e| format!("Keychain lookup for Secure Enclave key failed: {e}"))?;

    for res in search {
        if let SearchResult::Ref(Reference::Key(key)) = res {
            if let Ok(decrypted) =
                key.decrypt_data(Algorithm::ECIESEncryptionStandardX963SHA256AESGCM, wrapped)
            {
                if decrypted.len() == 32 {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&decrypted);
                    return Ok(out);
                }
            }
        }
    }

    Err("Apple Secure Enclave hardware unwrap failed or key not found. Ensure Touch ID is enabled, run with passphrase, or set INTERENV_ALLOW_MACOS_SOFTWARE_FALLBACK=1 for software fallback.".into())
}
