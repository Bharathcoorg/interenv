use keyring::Entry;
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "interenv";

/// Store the 32-byte master key in the OS hardware enclave / secure credential store.
pub fn store_key(project_id: &str, master_key: &[u8; 32]) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, project_id)
        .map_err(|e| format!("Keyring initialization error: {}", e))?;
    
    let key_hex = hex::encode(master_key);
    entry
        .set_password(&key_hex)
        .map_err(|e| format!("Failed to seal key in hardware/OS keyring: {}", e))?;
    
    Ok(())
}

/// Retrieve the 32-byte master key from the OS hardware enclave / secure credential store.
pub fn retrieve_key(project_id: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let entry = Entry::new(SERVICE_NAME, project_id)
        .map_err(|e| format!("Keyring initialization error: {}", e))?;
    
    let key_hex = entry
        .get_password()
        .map_err(|e| format!("Failed to retrieve key from hardware/OS keyring: {}. Was it locked on another machine?", e))?;
    
    let bytes = hex::decode(&key_hex)
        .map_err(|e| format!("Corrupted key in keyring: {}", e))?;
    
    if bytes.len() != 32 {
        return Err("Stored keyring key is not 32 bytes".into());
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
