use keyring::Entry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "interenv";

/// Master key wrapped with a platform-specific Key Encryption Key (KEK).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedMasterKey {
    /// Identifier of the Key Encryption Key scheme used to wrap the master key.
    pub kek_id: String,
    /// Wrapped master key ciphertext bytes.
    pub wrapped: Vec<u8>,
}

pub(crate) fn derive_kek_with_salt(salt: &[u8], project_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"interenv-kek-v3:");
    hasher.update(salt);
    hasher.update(project_id.as_bytes());
    let res = hasher.finalize();
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&res);
    kek
}

pub(crate) fn derive_kek_mask(project_id: &str) -> [u8; 32] {
    derive_kek_with_salt(b"", project_id)
}

#[cfg(windows)]
extern "system" {
    fn LocalFree(hmem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

#[cfg(windows)]
fn wrap_key_ncrypt(project_id: &str, master_key: &[u8; 32]) -> Result<(String, Vec<u8>), String> {
    use windows::Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptEncrypt, NCryptFinalizeKey, NCryptFreeObject,
        NCryptOpenKey, NCryptOpenStorageProvider, BCRYPT_AES_ALGORITHM, CERT_KEY_SPEC,
        MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
    };

    let mut prov = NCRYPT_PROV_HANDLE::default();
    // SAFETY: MS_PLATFORM_CRYPTO_PROVIDER is a valid provider name and prov receives handle.
    let open_res = unsafe { NCryptOpenStorageProvider(&mut prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
    if open_res.is_err() {
        return Err("TPM provider unavailable".to_string());
    }

    let key_name = format!("interenv-kek-{}", project_id);
    let key_name_w: Vec<u16> = key_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

    // SAFETY: key_name_w is a valid null-terminated wide string buffer.
    let open_key_res = unsafe {
        NCryptOpenKey(
            prov,
            &mut key_handle,
            windows::core::PCWSTR(key_name_w.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    };

    if open_key_res.is_err() {
        // SAFETY: prov is an open provider handle and key_name_w is null-terminated UTF-16.
        let create_res = unsafe {
            NCryptCreatePersistedKey(
                prov,
                &mut key_handle,
                BCRYPT_AES_ALGORITHM,
                windows::core::PCWSTR(key_name_w.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        };
        if create_res.is_err() {
            // SAFETY: prov is an open provider handle released upon creation failure.
            unsafe {
                let _ = NCryptFreeObject(prov);
            }
            return Err("Failed to create persisted TPM key".to_string());
        }

        // SAFETY: key_handle is a newly created persisted key handle.
        let finalize_res = unsafe { NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0)) };
        if finalize_res.is_err() {
            // SAFETY: handles are valid and released upon finalization error.
            unsafe {
                let _ = NCryptFreeObject(key_handle);
                let _ = NCryptFreeObject(prov);
            }
            return Err("Failed to finalize TPM key".to_string());
        }
    }

    let mut result_len = 0u32;
    // SAFETY: key_handle is valid; querying length with null output buffer.
    let query_res = unsafe {
        NCryptEncrypt(
            key_handle,
            Some(master_key),
            None,
            None,
            &mut result_len,
            NCRYPT_FLAGS(0),
        )
    };
    if query_res.is_err() || result_len == 0 {
        // SAFETY: handles are valid and released on query failure.
        unsafe {
            let _ = NCryptFreeObject(key_handle);
            let _ = NCryptFreeObject(prov);
        }
        return Err("NCrypt length query failed".to_string());
    }

    let mut ciphertext = vec![0u8; result_len as usize];
    // SAFETY: key_handle is valid and ciphertext has capacity of at least result_len bytes.
    let enc_res = unsafe {
        NCryptEncrypt(
            key_handle,
            Some(master_key),
            None,
            Some(&mut ciphertext),
            &mut result_len,
            NCRYPT_FLAGS(0),
        )
    };

    // SAFETY: key_handle and prov are valid handles being released.
    unsafe {
        let _ = NCryptFreeObject(key_handle);
        let _ = NCryptFreeObject(prov);
    }

    if enc_res.is_err() {
        return Err("NCrypt encryption failed".to_string());
    }

    ciphertext.truncate(result_len as usize);
    Ok(("windows-ncrypt-tpm-v2".to_string(), ciphertext))
}

#[cfg(windows)]
fn unwrap_key_ncrypt(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
    use windows::Win32::Security::Cryptography::{
        NCryptDecrypt, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, CERT_KEY_SPEC,
        MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
    };

    let mut prov = NCRYPT_PROV_HANDLE::default();
    // SAFETY: MS_PLATFORM_CRYPTO_PROVIDER is a valid provider name and prov receives handle.
    let open_res = unsafe { NCryptOpenStorageProvider(&mut prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
    if open_res.is_err() {
        return Err("TPM provider unavailable".to_string());
    }

    let key_name = format!("interenv-kek-{}", project_id);
    let key_name_w: Vec<u16> = key_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

    // SAFETY: key_name_w is a valid null-terminated wide string buffer.
    let open_key_res = unsafe {
        NCryptOpenKey(
            prov,
            &mut key_handle,
            windows::core::PCWSTR(key_name_w.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    };
    if open_key_res.is_err() {
        // SAFETY: prov is an open provider handle released on error.
        unsafe {
            let _ = NCryptFreeObject(prov);
        }
        return Err("Could not open persisted TPM key".to_string());
    }

    let mut result_len = 0u32;
    // SAFETY: key_handle is valid; querying length with null output buffer.
    let query_res = unsafe {
        NCryptDecrypt(
            key_handle,
            Some(wrapped),
            None,
            None,
            &mut result_len,
            NCRYPT_FLAGS(0),
        )
    };
    if query_res.is_err() || result_len == 0 {
        // SAFETY: handles are valid and released on query failure.
        unsafe {
            let _ = NCryptFreeObject(key_handle);
            let _ = NCryptFreeObject(prov);
        }
        return Err("NCrypt decrypt length query failed".to_string());
    }

    let mut plaintext = vec![0u8; result_len as usize];
    // SAFETY: key_handle is valid and plaintext has capacity of at least result_len bytes.
    let dec_res = unsafe {
        NCryptDecrypt(
            key_handle,
            Some(wrapped),
            None,
            Some(&mut plaintext),
            &mut result_len,
            NCRYPT_FLAGS(0),
        )
    };

    // SAFETY: key_handle and prov are valid handles being released.
    unsafe {
        let _ = NCryptFreeObject(key_handle);
        let _ = NCryptFreeObject(prov);
    }

    if dec_res.is_err() {
        return Err("NCrypt decryption failed".to_string());
    }

    if result_len != 32 {
        return Err(format!(
            "Decrypted key length mismatch: expected 32, got {}",
            result_len
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext[..32]);
    Ok(key)
}

#[cfg(windows)]
fn wrap_key_dpapi(project_id: &str, master_key: &[u8; 32]) -> Result<(String, Vec<u8>), String> {
    use rand::rngs::OsRng;
    use rand::RngCore;
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let data_in = CRYPT_INTEGER_BLOB {
        cbData: master_key.len() as u32,
        pbData: master_key.as_ptr() as *mut u8,
    };
    let mut entropy_bytes = derive_kek_with_salt(&salt, project_id);
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy_bytes.len() as u32,
        pbData: entropy_bytes.as_mut_ptr(),
    };
    let mut data_out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: data_in and entropy_blob point to valid contiguous memory buffers.
    let res = unsafe {
        CryptProtectData(
            &data_in,
            windows::core::PCWSTR::null(),
            Some(&entropy_blob),
            None,
            None,
            0,
            &mut data_out,
        )
    };
    if res.is_err() {
        return Err("DPAPI encryption error: could not wrap key".into());
    }
    // SAFETY: data_out.pbData points to data_out.cbData bytes allocated by DPAPI.
    let slice = unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) };
    let mut out_vec = salt.to_vec();
    out_vec.extend_from_slice(slice);
    // SAFETY: data_out.pbData was allocated by Win32 DPAPI and is freed with LocalFree.
    unsafe {
        let _ = LocalFree(data_out.pbData as _);
    }
    Ok(("windows-dpapi-tpm".to_string(), out_vec))
}

#[cfg(windows)]
fn unwrap_key_dpapi(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    // Try salted format first (salt[16] + dpapi_ciphertext)
    if wrapped.len() > 16 {
        let salt = &wrapped[..16];
        let ciphertext = &wrapped[16..];
        let data_in = CRYPT_INTEGER_BLOB {
            cbData: ciphertext.len() as u32,
            pbData: ciphertext.as_ptr() as *mut u8,
        };
        let mut entropy_bytes = derive_kek_with_salt(salt, project_id);
        let entropy_blob = CRYPT_INTEGER_BLOB {
            cbData: entropy_bytes.len() as u32,
            pbData: entropy_bytes.as_mut_ptr(),
        };
        let mut data_out = CRYPT_INTEGER_BLOB::default();
        let res = unsafe {
            CryptUnprotectData(
                &data_in,
                None,
                Some(&entropy_blob),
                None,
                None,
                0,
                &mut data_out,
            )
        };
        if res.is_ok() && !data_out.pbData.is_null() {
            let slice = unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) };
            if slice.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(slice);
                unsafe {
                    let _ = LocalFree(data_out.pbData as _);
                }
                return Ok(key);
            }
            unsafe {
                let _ = LocalFree(data_out.pbData as _);
            }
        }
    }

    // Fallback for legacy unsalted DPAPI payloads
    let data_in = CRYPT_INTEGER_BLOB {
        cbData: wrapped.len() as u32,
        pbData: wrapped.as_ptr() as *mut u8,
    };
    let mut entropy_bytes = derive_kek_mask(project_id);
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy_bytes.len() as u32,
        pbData: entropy_bytes.as_mut_ptr(),
    };
    let mut data_out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: data_in and entropy_blob point to valid contiguous memory buffers.
    let res = unsafe {
        CryptUnprotectData(
            &data_in,
            None,
            Some(&entropy_blob),
            None,
            None,
            0,
            &mut data_out,
        )
    };
    if res.is_err() || data_out.pbData.is_null() {
        return Err("DPAPI decryption error: could not unwrap key".into());
    }
    // SAFETY: data_out.pbData points to data_out.cbData bytes allocated by DPAPI.
    let slice = unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) };
    if slice.len() != 32 {
        // SAFETY: data_out.pbData is allocated by Win32 DPAPI and freed with LocalFree on error.
        unsafe {
            let _ = LocalFree(data_out.pbData as _);
        }
        return Err("Unwrapped key length mismatch: expected 32 bytes".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(slice);
    // SAFETY: data_out.pbData was allocated by Win32 DPAPI and is freed with LocalFree.
    unsafe {
        let _ = LocalFree(data_out.pbData as _);
    }
    Ok(key)
}

#[cfg(windows)]
fn wrap_key_platform(project_id: &str, master_key: &[u8; 32]) -> Result<(String, Vec<u8>), String> {
    match wrap_key_ncrypt(project_id, master_key) {
        Ok(res) => Ok(res),
        Err(e) => {
            eprintln!("⚠️  TPM 2.0 hardware KEK unavailable ({e}); falling back to Windows DPAPI.");
            wrap_key_dpapi(project_id, master_key)
        }
    }
}

#[cfg(windows)]
fn unwrap_key_platform(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
    if let Ok(key) = unwrap_key_ncrypt(project_id, wrapped) {
        return Ok(key);
    }
    unwrap_key_dpapi(project_id, wrapped)
}

#[cfg(target_os = "macos")]
fn wrap_key_platform(project_id: &str, master_key: &[u8; 32]) -> Result<(String, Vec<u8>), String> {
    crate::enclave::macos_secure_enclave::wrap_key_secure_enclave(project_id, master_key)
}

#[cfg(target_os = "macos")]
fn unwrap_key_platform(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
    crate::enclave::macos_secure_enclave::unwrap_key_secure_enclave(project_id, wrapped)
}

#[cfg(target_os = "linux")]
fn wrap_key_platform(project_id: &str, master_key: &[u8; 32]) -> Result<(String, Vec<u8>), String> {
    #[cfg(feature = "tpm")]
    {
        if let Ok(res) = crate::enclave::linux_tpm::wrap_key_tpm2(project_id, master_key) {
            return Ok(res);
        }
    }

    let tpm_active = std::path::Path::new("/sys/class/tpm/tpm0/device/active").exists()
        || std::path::Path::new("/dev/tpmrm0").exists()
        || std::path::Path::new("/dev/tpm0").exists();

    if tpm_active {
        eprintln!("ℹ️  TPM 2.0 detected; falling back to software KEK. Use 'interenv lock --passphrase' for passphrase-hardened keys in headless environments.");
    }

    let kek = derive_kek_mask(project_id);
    let mut masked = [0u8; 32];
    for i in 0..32 {
        masked[i] = master_key[i] ^ kek[i];
    }
    let kek_id = if tpm_active {
        "interenv-kek-v2-linux-tpm-fallback"
    } else {
        "interenv-kek-v2-linux-no-tpm"
    };
    Ok((kek_id.to_string(), masked.to_vec()))
}

#[cfg(target_os = "linux")]
fn unwrap_key_platform(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
    #[cfg(feature = "tpm")]
    {
        if let Ok(res) = crate::enclave::linux_tpm::unwrap_key_tpm2(project_id, wrapped) {
            return Ok(res);
        }
    }

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

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn wrap_key_platform(project_id: &str, master_key: &[u8; 32]) -> Result<(String, Vec<u8>), String> {
    let kek = derive_kek_mask(project_id);
    let mut masked = [0u8; 32];
    for i in 0..32 {
        masked[i] = master_key[i] ^ kek[i];
    }
    Ok(("interenv-kek-v2".to_string(), masked.to_vec()))
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn unwrap_key_platform(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
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

/// Wraps and stores a 256-bit master key in the platform OS / hardware keyring.
pub fn store_key(project_id: &str, master_key: &[u8; 32]) -> Result<WrappedMasterKey, String> {
    let entry = Entry::new(SERVICE_NAME, project_id)
        .map_err(|e| format!("Keyring initialization error: {}", e))?;

    let (kek_id, wrapped) = wrap_key_platform(project_id, master_key)?;
    let entry_val = format!("{}:{}", kek_id, hex::encode(&wrapped));
    let key_hex = Zeroizing::new(entry_val);
    entry
        .set_password(&key_hex)
        .map_err(|e| format!("Failed to seal key in hardware/OS keyring: {}", e))?;

    Ok(WrappedMasterKey { kek_id, wrapped })
}

/// Retrieves and unwraps the 256-bit master key from the platform OS / hardware keyring.
pub fn retrieve_key(project_id: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let entry = Entry::new(SERVICE_NAME, project_id)
        .map_err(|e| format!("Keyring initialization error: {}", e))?;

    let key_hex_str = Zeroizing::new(
        entry
            .get_password()
            .map_err(|e| format!("Hardware enclave retrieval error: {}", e))?,
    );

    let raw_val = key_hex_str.as_str();
    let (kek_id, hex_part) = if let Some(idx) = raw_val.find(':') {
        (&raw_val[..idx], &raw_val[idx + 1..])
    } else {
        ("", raw_val)
    };

    let wrapped = Zeroizing::new(
        hex::decode(hex_part).map_err(|e| format!("Corrupted keyring key hex: {}", e))?,
    );

    #[cfg(windows)]
    let raw_key = if kek_id == "windows-ncrypt-tpm-v2" {
        unwrap_key_ncrypt(project_id, &wrapped)
            .or_else(|_| unwrap_key_dpapi(project_id, &wrapped))?
    } else if kek_id == "windows-dpapi-tpm" {
        unwrap_key_dpapi(project_id, &wrapped)
            .or_else(|_| unwrap_key_ncrypt(project_id, &wrapped))?
    } else {
        unwrap_key_platform(project_id, &wrapped)?
    };

    #[cfg(target_os = "macos")]
    let raw_key = if kek_id == "macos-secure-enclave-v1" {
        crate::enclave::macos_secure_enclave::unwrap_key_secure_enclave(project_id, &wrapped)
            .or_else(|_| {
                crate::enclave::macos_secure_enclave::unwrap_key_macos_keychain_software(
                    project_id, &wrapped,
                )
            })?
    } else {
        unwrap_key_platform(project_id, &wrapped)?
    };

    #[cfg(target_os = "linux")]
    let raw_key = {
        #[cfg(feature = "tpm")]
        if kek_id == "linux-tpm2-v1" {
            crate::enclave::linux_tpm::unwrap_key_tpm2(project_id, &wrapped)
                .or_else(|_| unwrap_key_platform(project_id, &wrapped))?
        } else {
            unwrap_key_platform(project_id, &wrapped)?
        }
        #[cfg(not(feature = "tpm"))]
        unwrap_key_platform(project_id, &wrapped)?
    };

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    let raw_key = unwrap_key_platform(project_id, &wrapped)?;

    Ok(Zeroizing::new(raw_key))
}

/// Deletes the master key entry for a given project from the platform keyring.
pub fn delete_key(project_id: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, project_id)
        .map_err(|e| format!("Keyring initialization error: {}", e))?;

    match entry.delete_password() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Failed to delete key from keyring: {e}")),
    }
}
