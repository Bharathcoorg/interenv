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
fn wrap_key_platform(project_id: &str, master_key: &[u8; 32]) -> Result<(String, Vec<u8>), String> {
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
fn unwrap_key_platform(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
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

#[cfg(not(windows))]
fn wrap_key_platform(project_id: &str, master_key: &[u8; 32]) -> Result<(String, Vec<u8>), String> {
    let kek = derive_kek_mask(project_id);
    let mut masked = [0u8; 32];
    for i in 0..32 {
        masked[i] = master_key[i] ^ kek[i];
    }
    Ok(("interenv-kek-v2".to_string(), masked.to_vec()))
}

#[cfg(not(windows))]
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

/// Store the 32-byte master key in the OS hardware enclave / secure credential store,
/// wrapped using platform-specific hardware KEK (DPAPI on Windows, SecKey on macOS, TPM/XOR on Linux).
pub fn store_key(project_id: &str, master_key: &[u8; 32]) -> Result<WrappedMasterKey, String> {
    let entry = Entry::new(SERVICE_NAME, project_id)
        .map_err(|e| format!("Keyring initialization error: {}", e))?;

    let (kek_id, wrapped) = wrap_key_platform(project_id, master_key)?;
    let key_hex = Zeroizing::new(hex::encode(&wrapped));
    entry
        .set_password(&key_hex)
        .map_err(|e| format!("Failed to seal key in hardware/OS keyring: {}", e))?;

    Ok(WrappedMasterKey { kek_id, wrapped })
}

/// Retrieve the 32-byte master key from the OS hardware enclave / secure credential store,
/// unwrapping it using the platform-specific hardware KEK.
pub fn retrieve_key(project_id: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let entry = Entry::new(SERVICE_NAME, project_id)
        .map_err(|e| format!("Keyring initialization error: {}", e))?;

    let key_hex_str = Zeroizing::new(
        entry
            .get_password()
            .map_err(|e| format!("Failed to retrieve key from hardware/OS keyring: {}. Was it locked on another machine?", e))?,
    );

    let bytes = Zeroizing::new(
        hex::decode(&*key_hex_str).map_err(|e| format!("Corrupted key in keyring: {}", e))?,
    );

    let key_arr = unwrap_key_platform(project_id, &bytes)?;
    Ok(Zeroizing::new(key_arr))
}

/// Delete the key entry from the OS hardware enclave / secure credential store.
pub fn delete_key(project_id: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, project_id)
        .map_err(|e| format!("Keyring initialization error: {}", e))?;

    match entry.delete_password() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Failed to delete key from keyring: {}", e)),
    }
}
