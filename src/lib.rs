//! # interenv
//!
//! Hardware-Enclave Protected Secrets for Terminal & Git (Zero Plaintext `.env` on Disk).
//! Built by Interlayer for ultra-secure, local-first secret management.

pub mod cli;
pub mod crypto;
pub mod enclave;
pub mod envfile;
pub mod git;
pub mod runner;
pub mod shredder;

use sha2::{Digest, Sha256};
use std::path::Path;

pub use envfile::lockfile::InterLock;
pub use envfile::parser::EnvMap;
pub use envfile::Secrets;

/// Compute a stable project ID bound to repository anchors (.git/HEAD, manifests)
/// ensuring folder renaming keeps the same ID if the repo is unchanged.
pub fn compute_project_id(cwd: &Path) -> (String, String) {
    let canonical = dunce::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let folder_name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string();

    let mut hasher = Sha256::new();
    let mut has_stable_anchor = false;

    // 1. Content of .git/HEAD (if present)
    let git_head = canonical.join(".git").join("HEAD");
    if let Ok(head_bytes) = std::fs::read(&git_head) {
        hasher.update(&head_bytes);
        has_stable_anchor = true;
    }

    // 2. First 1KB of Cargo.toml or package.json (whichever exists)
    let cargo_toml = canonical.join("Cargo.toml");
    let package_json = canonical.join("package.json");
    let mut manifest_name = None;

    if let Ok(bytes) = std::fs::read(&cargo_toml) {
        let slice = &bytes[..bytes.len().min(1024)];
        hasher.update(slice);
        has_stable_anchor = true;
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
        has_stable_anchor = true;
    }

    // 3. Fall back to folder name if neither exists
    if !has_stable_anchor {
        hasher.update(folder_name.as_bytes());
    }

    let project_name = manifest_name.unwrap_or_else(|| folder_name.clone());
    let hash = hex::encode(hasher.finalize());
    let project_id = format!("{}-{}", project_name, &hash[..16]);
    (project_id, project_name)
}
