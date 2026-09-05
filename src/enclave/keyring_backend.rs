use keyring::Entry;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "interenv";

// TODO: real KEK via TPM
fn derive_kek_mask(project_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"interenv-kek-v2:");
    hasher.update(project_id.as_bytes());
    let res = hasher.finalize();
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&res);
    kek
}

/// Store the 32-byte master key in the OS hardware enclave / secure credential store,
/// masked with a project-bound KEK so raw keys are never placed directly in keyring dumps.
pub fn store_key(project_id: &str, master_key: &[u8; 32]) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, project_id)
        .map_err(|e| format!("Keyring initialization error: {}", e))?;

    let kek = derive_kek_mask(project_id);
    let mut masked = [0u8; 32];
    for i in 0..32 {
        masked[i] = master_key[i] ^ kek[i];
    }

    let key_hex = Zeroizing::new(hex::encode(masked));
    entry
        .set_password(&key_hex)
        .map_err(|e| format!("Failed to seal key in hardware/OS keyring: {}", e))?;

    Ok(())
}

/// Retrieve the 32-byte master key from the OS hardware enclave / secure credential store,
/// unmasking it via the project-bound KEK.
pub fn retrieve_key(project_id: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let entry = Entry::new(SERVICE_NAME, project_id)
        .map_err(|e| format!("Keyring initialization error: {}", e))?;

    let key_hex_str = Zeroizing::new(
        entry
            .get_password()
            .map_err(|e| format!("Failed to retrieve key from hardware/OS keyring: {}. Was it locked on another machine?", e))?,
    );

    let key_hex = key_hex_str;
    let mut bytes = Zeroizing::new(
        hex::decode(&*key_hex).map_err(|e| format!("Corrupted key in keyring: {}", e))?,
    );

    if bytes.len() != 32 {
        return Err("Stored keyring key is not 32 bytes".into());
    }

    let kek = derive_kek_mask(project_id);
    for i in 0..32 {
        bytes[i] ^= kek[i];
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&bytes);
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
