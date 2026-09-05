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

pub use envfile::lockfile::InterLock;
pub use envfile::parser::EnvMap;
