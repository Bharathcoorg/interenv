use std::fs;
use std::path::{Path, PathBuf};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::crypto::cipher::EncryptedPayload;

pub const DEFAULT_LOCK_FILE: &str = ".interenv.lock";
pub const LEGACY_LOCK_FILE: &str = "interenv.lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProviderType {
    /// Stored in OS Hardware Enclave / Secure Credential Store (TouchID, TPM, Windows Credential Manager)
    HardwareEnclave,
    /// Encrypted with an Argon2id derived passphrase (for CI/CD or headless environments)
    Passphrase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterLock {
    pub version: String,
    pub project_id: String,
    pub project_name: String,
    pub key_provider: KeyProviderType,
    pub kdf_salt_hex: String,
    pub payload: EncryptedPayload,
    pub keys_count: usize,
    pub key_names: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl InterLock {
    pub fn new(
        project_id: String,
        project_name: String,
        key_provider: KeyProviderType,
        kdf_salt_hex: String,
        payload: EncryptedPayload,
        key_names: Vec<String>,
    ) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            version: "1.0".to_string(),
            project_id,
            project_name,
            key_provider,
            kdf_salt_hex,
            keys_count: key_names.len(),
            key_names,
            payload,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    /// Save the lockfile to the specified path formatted as pretty JSON.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialization error: {}", e))?;
        fs::write(path.as_ref(), json)
            .map_err(|e| format!("Failed to write lockfile {}: {}", path.as_ref().display(), e))?;
        Ok(())
    }

    /// Load the lockfile from the specified path.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Cannot read lockfile {}: {}", path.as_ref().display(), e))?;
        let lock: Self = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid lockfile JSON: {}", e))?;
        Ok(lock)
    }

    /// Discover `.interenv.lock` in the current directory or by walking up parent directories.
    pub fn find_lockfile(start_dir: &Path) -> Option<PathBuf> {
        let mut curr = dunce::canonicalize(start_dir).unwrap_or_else(|_| start_dir.to_path_buf());
        loop {
            let primary = curr.join(DEFAULT_LOCK_FILE);
            if primary.exists() && primary.is_file() {
                return Some(primary);
            }
            let secondary = curr.join(LEGACY_LOCK_FILE);
            if secondary.exists() && secondary.is_file() {
                return Some(secondary);
            }
            if !curr.pop() {
                break;
            }
        }
        None
    }
}
