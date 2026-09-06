use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::cipher::EncryptedPayload;
use crate::crypto::kdf::{OWASP_ARGON2_ITERATIONS, OWASP_ARGON2_MEM_KIB, OWASP_ARGON2_PARALLELISM};

/// Default lockfile filename.
pub const DEFAULT_LOCK_FILE: &str = ".interenv.lock";
/// Legacy lockfile filename (unhidden).
pub const LEGACY_LOCK_FILE: &str = "interenv.lock";
/// Current lockfile schema version.
pub const CURRENT_LOCK_VERSION: &str = "3.0";

/// Key provider type used to derive or retrieve the master encryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProviderType {
    /// Stored in OS Hardware Enclave / Secure Credential Store (TouchID, TPM, Windows Credential Manager)
    #[default]
    HardwareEnclave,
    /// Encrypted with an Argon2id derived passphrase (for CI/CD or headless environments)
    Passphrase,
}

/// Parameters configured for Argon2id key derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// KDF algorithm identifier (argon2id).
    pub algo: String,
    /// Memory cost in KiB.
    pub mem_kib: u32,
    /// Iteration count.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
    /// Argon2 version specification.
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

fn default_min_compatible_version() -> String {
    "1.0".to_string()
}

fn default_cipher() -> String {
    "xchacha20-poly1305".to_string()
}

fn default_payload() -> EncryptedPayload {
    EncryptedPayload {
        nonce_hex: String::new(),
        ciphertext_hex: String::new(),
    }
}

/// Represents the encrypted state and cryptographic metadata of an InterEnv project.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterLock {
    /// Lockfile schema version.
    #[serde(default = "default_version")]
    pub version: String,
    /// Minimum version of InterEnv required to read this lockfile.
    #[serde(default = "default_min_compatible_version")]
    pub min_compatible_version: String,
    /// Unique project identifier.
    #[serde(default)]
    pub project_id: String,
    /// Human-readable project name.
    #[serde(default)]
    pub project_name: String,
    /// Provider type for master key storage/derivation.
    #[serde(default)]
    pub key_provider: KeyProviderType,
    /// Random salt for KDF in hexadecimal representation.
    #[serde(default)]
    pub kdf_salt_hex: String,
    /// Argon2id parameters.
    #[serde(default)]
    pub kdf: KdfParams,
    /// Cipher algorithm identifier.
    #[serde(default = "default_cipher")]
    pub cipher: String,
    /// Encrypted ciphertext and nonce payload.
    #[serde(default = "default_payload")]
    pub payload: EncryptedPayload,
    /// Count of secret keys stored.
    #[serde(default)]
    pub keys_count: usize,
    /// Names of environment variables secured (values omitted).
    #[serde(default)]
    pub key_names: Vec<String>,
    /// RFC 3339 creation timestamp.
    #[serde(default)]
    pub created_at: String,
    /// RFC 3339 last update timestamp.
    #[serde(default)]
    pub updated_at: String,
}

impl InterLock {
    /// Construct a new InterLock instance with latest schema v3.0 defaults.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: String,
        project_name: String,
        key_provider: KeyProviderType,
        kdf_salt_hex: String,
        payload: EncryptedPayload,
        key_names: Vec<String>,
        kdf: KdfParams,
        cipher: String,
    ) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            version: CURRENT_LOCK_VERSION.to_string(),
            min_compatible_version: "1.0".to_string(),
            project_id,
            project_name,
            key_provider,
            kdf_salt_hex,
            kdf,
            cipher,
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

    /// Load the lockfile from the specified path, validating schema compatibility.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Cannot read lockfile {}: {}", path.as_ref().display(), e))?;
        let lock: Self =
            serde_json::from_str(&content).map_err(|e| format!("Invalid lockfile JSON: {}", e))?;

        let parse_version = |v: &str| -> (u32, u32) {
            let mut parts = v.split('.');
            let maj = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let min = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            (maj, min)
        };

        if parse_version(&lock.version) < parse_version(&lock.min_compatible_version) {
            return Err(format!(
                "Lockfile version {} is older than required minimum compatible version {}. Please re-lock using 'interenv lock --force' or 'interenv edit'.",
                lock.version, lock.min_compatible_version
            ));
        }

        Ok(lock)
    }

    /// Discover `.interenv.lock` in the current directory or by walking up parent directories.
    pub fn find_lockfile(start_dir: &Path) -> Option<PathBuf> {
        let mut curr =
            crate::util::safe_canonicalize(start_dir).unwrap_or_else(|_| start_dir.to_path_buf());
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
