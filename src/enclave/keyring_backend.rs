use keyring::Entry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "interenv";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedMasterKey {
    pub kek_id: String,
    pub wrapped: Vec<u8>,
}

fn derive_kek_mask(project_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"interenv-kek-v2:");
    hasher.update(project_id.as_bytes());
    let res = hasher.finalize();
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&res);
    kek
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
        NCRYPT_USE_VIRTUAL_ISOLATION_FLAG,
    };

    let mut prov = NCRYPT_PROV_HANDLE::default();
    let open_res = unsafe { NCryptOpenStorageProvider(&mut prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
    if open_res.is_err() {
        return Err("TPM provider unavailable".to_string());
    }

    let key_name = format!("interenv-kek-{}", project_id);
    let key_name_w: Vec<u16> = key_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

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
        let create_res = unsafe {
            NCryptCreatePersistedKey(
                prov,
                &mut key_handle,
                BCRYPT_AES_ALGORITHM,
                windows::core::PCWSTR(key_name_w.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(NCRYPT_USE_VIRTUAL_ISOLATION_FLAG),
            )
        };
        if create_res.is_err() {
            unsafe {
                let _ = NCryptFreeObject(prov);
            }
            return Err("Failed to create persisted TPM key".to_string());
        }

        let finalize_res = unsafe { NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0)) };
        if finalize_res.is_err() {
            unsafe {
                let _ = NCryptFreeObject(key_handle);
                let _ = NCryptFreeObject(prov);
            }
            return Err("Failed to finalize TPM key".to_string());
        }
    }

    let mut result_len = 0u32;
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
        unsafe {
            let _ = NCryptFreeObject(key_handle);
            let _ = NCryptFreeObject(prov);
        }
        return Err("NCrypt length query failed".to_string());
    }

    let mut ciphertext = vec![0u8; result_len as usize];
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
    let open_res = unsafe { NCryptOpenStorageProvider(&mut prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
    if open_res.is_err() {
        return Err("TPM provider unavailable".to_string());
    }

    let key_name = format!("interenv-kek-{}", project_id);
    let key_name_w: Vec<u16> = key_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

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
        unsafe {
            let _ = NCryptFreeObject(prov);
        }
        return Err("Could not open persisted TPM key".to_string());
    }

    let mut result_len = 0u32;
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
        unsafe {
            let _ = NCryptFreeObject(key_handle);
            let _ = NCryptFreeObject(prov);
        }
        return Err("NCrypt decrypt length query failed".to_string());
    }

    let mut plaintext = vec![0u8; result_len as usize];
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
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};
    let data_in = CRYPT_INTEGER_BLOB {
        cbData: master_key.len() as u32,
        pbData: master_key.as_ptr() as *mut u8,
    };
    let mut entropy_bytes = derive_kek_mask(project_id);
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy_bytes.len() as u32,
        pbData: entropy_bytes.as_mut_ptr(),
    };
    let mut data_out = CRYPT_INTEGER_BLOB::default();
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
    let slice = unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) };
    let vec = slice.to_vec();
    unsafe {
        let _ = LocalFree(data_out.pbData as _);
    }
    Ok(("windows-dpapi-tpm".to_string(), vec))
}

#[cfg(windows)]
fn unwrap_key_dpapi(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
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
    if res.is_err() {
        return Err("DPAPI decryption error: could not unwrap key".into());
    }
    let slice = unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) };
    if slice.len() != 32 {
        unsafe {
            let _ = LocalFree(data_out.pbData as _);
        }
        return Err("Unwrapped key length mismatch: expected 32 bytes".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(slice);
    unsafe {
        let _ = LocalFree(data_out.pbData as _);
    }
    Ok(key)
}

#[cfg(windows)]
fn wrap_key_platform(project_id: &str, master_key: &[u8; 32]) -> Result<(String, Vec<u8>), String> {
    match wrap_key_ncrypt(project_id, master_key) {
        Ok(res) => Ok(res),
        Err(_) => wrap_key_dpapi(project_id, master_key),
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
    let kek = derive_kek_mask(project_id);
    let mut masked = [0u8; 32];
    for i in 0..32 {
        masked[i] = master_key[i] ^ kek[i];
    }
    Ok(("macos-keychain-kek-v2".to_string(), masked.to_vec()))
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "linux")]
fn wrap_key_platform(project_id: &str, master_key: &[u8; 32]) -> Result<(String, Vec<u8>), String> {
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

pub fn retrieve_key(project_id: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let entry = Entry::new(SERVICE_NAME, project_id)
        .map_err(|e| format!("Keyring initialization error: {}", e))?;

    let key_hex_str = Zeroizing::new(
        entry
            .get_password()
            .map_err(|e| format!("Hardware enclave retrieval error: {}", e))?,
    );

    let raw_val = key_hex_str.as_str();
    let (_kek_id, hex_part) = if let Some(idx) = raw_val.find(':') {
        (&raw_val[..idx], &raw_val[idx + 1..])
    } else {
        ("", raw_val)
    };

    let wrapped = Zeroizing::new(
        hex::decode(hex_part).map_err(|e| format!("Corrupted keyring key hex: {}", e))?,
    );

    #[cfg(windows)]
    let raw_key = if _kek_id == "windows-ncrypt-tpm-v2" {
        unwrap_key_ncrypt(project_id, &wrapped)
            .or_else(|_| unwrap_key_dpapi(project_id, &wrapped))?
    } else if _kek_id == "windows-dpapi-tpm" {
        unwrap_key_dpapi(project_id, &wrapped)
            .or_else(|_| unwrap_key_ncrypt(project_id, &wrapped))?
    } else {
        unwrap_key_platform(project_id, &wrapped)?
    };

    #[cfg(not(windows))]
    let raw_key = unwrap_key_platform(project_id, &wrapped)?;

    Ok(Zeroizing::new(raw_key))
}

pub fn delete_key(project_id: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, project_id)
        .map_err(|e| format!("Keyring initialization error: {}", e))?;

    match entry.delete_password() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Failed to delete key from keyring: {}", e)),
    }
}
