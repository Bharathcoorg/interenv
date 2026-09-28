//! macOS Secure Enclave hardware Key Encryption Key (KEK) implementation.

#[cfg(target_os = "macos")]
/// Wrap master encryption key using Apple Secure Enclave hardware key.
pub fn wrap_key_secure_enclave(
    project_id: &str,
    master_key: &[u8; 32],
) -> Result<(String, Vec<u8>), String> {
    use security_framework::access_control::{AccessControlOptions, ProtectionMode, SecAccessControl};
    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

    let key_label = format!("interenv-se-{}", project_id);

    #[allow(deprecated)]
    let options = GenerateKeyOptions {
        key_type: Some(KeyType::ec()),
        size_in_bits: Some(256),
        label: Some(key_label),
        token: Some(Token::SecureEnclave),
        location: None,
        access_control: Some(
            SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                (AccessControlOptions::USER_PRESENCE | AccessControlOptions::PRIVATE_KEY_USAGE).bits(),
            )
            .map_err(|e| format!("Failed to configure Secure Enclave access control: {e}"))?,
        ),
    };

    let key = SecKey::new(&options).map_err(|e| {
        format!(
"Apple Secure Enclave hardware key generation failed ({e}). Use 'interenv lock --passphrase' or the OS credential-store fallback."
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
/// Unwrap master encryption key using Apple Secure Enclave hardware key.
pub fn unwrap_key_secure_enclave(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
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

    Err("Apple Secure Enclave hardware unwrap failed or key not found. Re-lock with passphrase or the OS credential-store provider.".into())
}
