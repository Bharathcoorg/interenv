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
///
/// Only *derived* identifiers are hashed — the extracted project name, the git
/// HEAD reference, and the folder name. Raw manifest bytes are never fed into
/// the hash, so a secret that happens to appear in the first 1024 bytes of a
/// `Cargo.toml`/`package.json` cannot leak into the plaintext project ID that is
/// stored in the lockfile.
pub fn compute_project_id(cwd: &Path) -> (String, String) {
    let canonical = safe_canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let folder_name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string();

    let mut hasher = Sha256::new();

    // Hash the git HEAD reference (branch/commit pointer) so the ID is bound
    // to the repository's current state.
    let git_head = canonical.join(".git").join("HEAD");
    if let Ok(head_bytes) = std::fs::read(&git_head) {
        hasher.update(&head_bytes);
    }

    // Hash the *extracted* project name, not the raw manifest bytes. The name
    // is a single, well-formed identifier and carries no risk of embedding
    // unrelated manifest content (including secrets) into the ID.
    let manifest_name = read_manifest_name(&canonical.join("Cargo.toml"))
        .or_else(|| read_manifest_name(&canonical.join("package.json")));

    let project_name = manifest_name.unwrap_or_else(|| folder_name.clone());
    hasher.update(project_name.as_bytes());
    hasher.update(folder_name.as_bytes());

    let hash = hex::encode(hasher.finalize());
    let project_id = format!("{}-{}", project_name, &hash[..16]);
    (project_id, project_name)
}

/// Extract the project name from a `Cargo.toml` or `package.json` manifest.
/// Only the `name` field is read; no other manifest content is returned, so
/// callers cannot accidentally propagate manifest bytes into a hash or ID.
fn read_manifest_name(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let slice = &bytes[..bytes.len().min(1024)];
    let s = std::str::from_utf8(slice).ok()?;

    if path.extension().is_some_and(|e| e == "json") {
        // package.json: parse the top-level "name" field with a minimal scan
        // to avoid pulling in a JSON dependency.
        for line in s.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("\"name\"") {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix(':') {
                    let rest = rest.trim_start();
                    if let Some(rest) = rest.strip_prefix('"') {
                        if let Some(end) = rest.find('"') {
                            let name = &rest[..end];
                            if !name.is_empty() {
                                return Some(name.to_string());
                            }
                        }
                    }
                }
            }
        }
        return None;
    }

    // Cargo.toml: `name = "..."` (table header `name = "..."` is also valid).
    for line in s.lines() {
        let trimmed = line.trim();
        if let Some(n) = trimmed.strip_prefix("name = \"") {
            if let Some(end) = n.strip_suffix('"') {
                if !end.is_empty() {
                    return Some(end.to_string());
                }
            }
        }
    }
    None
}
