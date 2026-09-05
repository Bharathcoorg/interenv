use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::cipher::{EncryptedPayload, CIPHER_XCHACHA20_POLY1305};
use crate::crypto::kdf::{OWASP_ARGON2_ITERATIONS, OWASP_ARGON2_MEM_KIB, OWASP_ARGON2_PARALLELISM};

pub const DEFAULT_LOCK_FILE: &str = ".interenv.lock";
pub const LEGACY_LOCK_FILE: &str = "interenv.lock";
pub const CURRENT_LOCK_VERSION: &str = "2.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProviderType {
    /// Stored in OS Hardware Enclave / Secure Credential Store (TouchID, TPM, Windows Credential Manager)
    #[default]
    HardwareEnclave,
    /// Encrypted with an Argon2id derived passphrase (for CI/CD or headless environments)
    Passphrase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub algo: String,
    pub mem_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub version: String,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algo: "argon2id".to_string(),
            mem_kib: OWASP_ARGON2_MEM_KIB,
            iterations: OWASP_ARGON2_ITERATIONS,
            parallelism: OWASP_ARGON2_PARALLELISM,
            version: "0x13".to_string(),
        }
    }
}

fn default_version() -> String {
    "1.0".to_string()
}

fn default_cipher() -> String {
    "aes-256-gcm".to_string()
}

fn default_payload() -> EncryptedPayload {
    EncryptedPayload {
        nonce_hex: String::new(),
        ciphertext_hex: String::new(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterLock {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub project_name: String,
    #[serde(default)]
    pub key_provider: KeyProviderType,
    #[serde(default)]
    pub kdf_salt_hex: String,
    #[serde(default)]
    pub kdf: KdfParams,
    #[serde(default = "default_cipher")]
    pub cipher: String,
    #[serde(default = "default_payload")]
    pub payload: EncryptedPayload,
    #[serde(default)]
    pub keys_count: usize,
    #[serde(default)]
    pub key_names: Vec<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
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
            version: CURRENT_LOCK_VERSION.to_string(),
            project_id,
            project_name,
            key_provider,
            kdf_salt_hex,
            kdf: KdfParams::default(),
            cipher: CIPHER_XCHACHA20_POLY1305.to_string(),
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
        fs::write(path.as_ref(), json).map_err(|e| {
            format!(
                "Failed to write lockfile {}: {}",
                path.as_ref().display(),
                e
            )
        })?;
        Ok(())
    }

    /// Load the lockfile from the specified path.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Cannot read lockfile {}: {}", path.as_ref().display(), e))?;
        let lock: Self =
            serde_json::from_str(&content).map_err(|e| format!("Invalid lockfile JSON: {}", e))?;
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
