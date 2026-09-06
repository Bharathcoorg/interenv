//! # interenv
//!
//! Hardware-Enclave Protected Secrets for Terminal & Git (Zero Plaintext `.env` on Disk).
//! Built by Interlayer for ultra-secure, local-first secret management.

#![deny(missing_docs)]

/// Command-line argument parsing and definition structures.
pub mod cli;
/// Cryptographic primitives including XChaCha20-Poly1305 and Argon2id KDF.
pub mod crypto;
/// Hardware enclave and OS keyring integration backends.
pub mod enclave;
/// Dotenv file parser, secrets container, and lockfile schema.
pub mod envfile;
/// Git pre-commit hooks and secret scanning logic.
pub mod git;
/// Process execution runner with platform-specific sandboxing.
pub mod runner;
/// DoD 5220.22-M 3-pass file shredder with platform decommitment.
pub mod shredder;
/// Shared utilities including symlink-safe canonicalization.
pub mod util;

use sha2::{Digest, Sha256};
use std::path::Path;

pub use envfile::lockfile::InterLock;
pub use envfile::parser::EnvMap;
pub use envfile::Secrets;
pub use util::safe_canonicalize;

/// Compute a stable project ID bound to repository anchors (.git/HEAD, manifests)
/// and folder name, preventing collisions across different folder names (M-9).
pub fn compute_project_id(cwd: &Path) -> (String, String) {
    let canonical = safe_canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let folder_name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string();

    let mut hasher = Sha256::new();

    let git_head = canonical.join(".git").join("HEAD");
    if let Ok(head_bytes) = std::fs::read(&git_head) {
        hasher.update(&head_bytes);
    }

    let cargo_toml = canonical.join("Cargo.toml");
    let package_json = canonical.join("package.json");
    let mut manifest_name = None;

    if let Ok(bytes) = std::fs::read(&cargo_toml) {
        let slice = &bytes[..bytes.len().min(1024)];
        hasher.update(slice);
        if let Ok(s) = std::str::from_utf8(slice) {
            for line in s.lines() {
                let trimmed = line.trim();
                if let Some(n) = trimmed.strip_prefix("name = \"") {
                    if let Some(end) = n.strip_suffix('"') {
                        manifest_name = Some(end.to_string());
                        break;
                    }
                }
            }
        }
    } else if let Ok(bytes) = std::fs::read(&package_json) {
        let slice = &bytes[..bytes.len().min(1024)];
        hasher.update(slice);
    }

    hasher.update(folder_name.as_bytes());

    let project_name = manifest_name.unwrap_or_else(|| folder_name.clone());
    let hash = hex::encode(hasher.finalize());
    let project_id = format!("{}-{}", project_name, &hash[..16]);
    (project_id, project_name)
}
