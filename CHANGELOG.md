# Changelog

All notable changes to **InterEnv** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.1] - 2026-09-07

### Security Hardening, Multi-Platform Enclave Upgrades & SDK Release Fixes

#### Cryptography & Hardware Enclaves
- **Linux TPM 2.0 Genuine Hardware Key Sealing**: Replaced XOR mask key wrapping with real TPM 2.0 object sealing via `tss-esapi 7.7.0` (`linux-tpm2-v2`). Generates an RSA 2048 primary storage key under `Hierarchy::Owner` and creates a child `KeyedHash` containing the 32-byte master key with fixed TPM and owner authorization attributes.
- **macOS Secure Enclave Hardware Binding**: Integrated `security-framework` crate for hardware-backed P-256 EC key generation (`Token::SecureEnclave`) and ECIES encryption/decryption (`macos-secure-enclave-v1`). Added 48-byte salted KEK (`macos-keychain-kek-v3`) with 16-byte random salt for headless fallback environments.
- **Windows NCrypt & DPAPI Isolation**: Enforced strict KEK dispatch (`windows-ncrypt-tpm-v2` vs `windows-dpapi-tpm`), eliminating silent fallback from hardware TPM to software DPAPI on retrieval.
- **Salted Software KEKs**: All fallback software KEK derivation now uses a fresh 16-byte random salt via `OsRng` with HKDF-SHA256, formatted as 48 bytes with backwards compatibility for legacy 32-byte entries.

#### Process Sandbox & Child Execution
- **Linux Parent-Death Cleanup**: Registered `libc::prctl(PR_SET_PDEATHSIG, SIGKILL)` in child `pre_exec` before `setsid()` with defensive parent PID check to prevent orphaned processes containing decrypted secrets.
- **Linux Seccomp BPF Rules**: Upgraded filter rules to unconditionally match and deny `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, and `unshare`.
- **macOS Sandbox Profile**: Configured profile to allow working directory development operations by default while maintaining isolation from unauthorized system access.
- **PATH Hijacking Defense**: Sanitized `PATH` traversal in executable lookup to ignore relative directories and enforce standard Windows binary extension precedence (`.exe` > `.cmd` > `.bat`).

#### File Shredder & Safety Net
- **Symlink Defenses**: Added symlink metadata checks and `O_NOFOLLOW` file descriptor flags to reject shredding symlink targets and prevent redirection attacks.
- **Block Device Guard**: Confirmed target file is a block special device (`S_IFBLK`) prior to issuing `BLKDISCARD` ioctl commands on Linux.
- **Alternate Data Stream Sanitization**: Validated Windows NTFS ADS stream names against a strict alphanumeric whitelist.

#### Multi-Ecosystem SDKs
- **NPM Package Postinstall**: Fixed critical bug in `scripts/install.js` where lack of bundled prebuilds caused `npm install interenv` to exit with error code 1. Now checks system `PATH` and exits cleanly with 0 while logging helpful CLI install instructions.
- **Developer Error Diagnostics**: Enhanced Node.js, Python, Go, and PHP SDKs with clear actionable messages when the native `interenv` binary is missing from `PATH`.
- **Prebuilds Packaging**: Added `"prebuilds"` directory to `package.json` `"files"`.

---

## [1.0.0] - 2026-09-06

### Major Release (v1.0.0 Release Candidate & General Availability)

#### Section 1: Complete Hardware KEK Implementation
- **macOS Secure Enclave**: Added direct Apple Security framework integration (`src/enclave/macos_secure_enclave.rs`) using `SecKeyGenerate` with `ec_sec_key_transport_secp256r1`, user presence access control, and ECIES decryption via `SecKeyAlgorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM` (`macos-secure-enclave-v1`), with transparent fallback to Keychain software KEK.
- **Linux TPM 2.0**: Added optional `tss-esapi` hardware TPM 2.0 KEK binding (`src/enclave/linux_tpm.rs`) under `features = ["tpm"]`, with primary AES/RSA key binding and hardware-derived mask XOR encryption (`linux-tpm2-v1`).

#### Section 2: Supply Chain Hardening
- **Cargo Sparse Registry & Lockfile**: Switched crates.io to sparse protocol and CLI git fetch in `.cargo/config.toml`. Enforced committed `Cargo.lock` integrity in CI.
- **cargo-audit & cargo-deny**: Integrated `.github/workflows/security.yml` with `audit-check`, `cargo-deny` with `deny.toml` (licenses, bans, sources, advisories), and `cargo-outdated`.
- **Reproducible Builds**: Configured release profile with `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`, `overflow-checks = true`, debug stripped, and `--remap-path-prefix` rustflag in `.cargo/config.toml`. Added `scripts/verify-reproducible-build.sh`.

#### Section 3: Comprehensive Test Coverage
- **Fuzz Testing**: Implemented standalone `fuzz/` workspace with 3 LibFuzzer targets: `parse_dotenv`, `decrypt_payload`, and `kdf_input`. Added fuzz job to GitHub Actions CI.
- **Crypto Property Testing**: Added `tests/crypto_proptest.rs` testing arbitrary size round-trips up to 4096 bytes, ciphertext bit tampering detection, nonce bit tampering detection, and 50,000-iteration nonce collision resistance.
- **Cross-Platform Integration Tests**: Added `tests/cross_platform.rs` verifying Linux hole punching, seccomp ptrace blocking, macOS sandbox root write restrictions, and Windows Job Object child lifecycle.

#### Section 4: Security Policy & Disclosure
- **Threat Model & Reporting**: Augmented `SECURITY.md` with explicit Threat Model v1.0, documented protected/unprotected attack surfaces, and 72-hour coordinated disclosure contact.
- **RFC 9116 security.txt**: Added root `security.txt` pointing to security contact and canonical advisory URL.

#### Section 5: CI/CD Hardening
- **Multi-OS Matrix**: Upgraded `.github/workflows/ci.yml` across Ubuntu, macOS, and Windows with both `stable` and `beta` Rust toolchains, testing `--release --locked` builds, clippy, and rustfmt.
- **Developer Pre-commit Config**: Created `.pre-commit-config.yaml` for automated repository hygiene (formatting, linting, TOML, YAML).

#### Section 6: Comprehensive Documentation
- **THREAT_MODEL.md**: Authored comprehensive security threat model covering assets, adversaries, trust boundaries, mitigations, and residual risks.
- **ARCHITECTURE.md**: Documented system architecture with layer diagrams covering crypto, storage, execution, shredder, git, and Node SDK.
- **README.md**: Expanded with comparative tool analysis (dotenv-vault, sops, git-crypt), security guarantees matrix, platform support matrix, limitations, and reproducible build instructions.

#### Section 7: Performance Benchmarks
- **Criterion Benchmarks**: Created `benches/crypto.rs` benchmarking 4KiB encryption, 4KiB decryption, and Argon2id KDF derivation.

#### Section 8: Multi-Ecosystem Release Automation
- **Release Automation**: Configured `.github/workflows/release.yml` with cross-compiled release binaries (Linux x86_64, macOS aarch64 & x86_64, Windows x86_64) and automated publishing to Crates.io, npm, PyPI, Packagist, and Go modules.

#### Section 9: Final Code Quality & Audit
- **Unsafe Code Elimination**: Verified every `unsafe` block across all modules with concise safety invariant comments (max 3 lines).
- **Zero Undocumented Items**: Enforced `#![deny(missing_docs)]` in `src/lib.rs` and documented all public types, functions, and modules.
- **Strict Clippy**: Configured `[lints.clippy]` with `pedantic = "warn"` and resolved all lint warnings.

#### Section 10: Backward Compatibility & Cleanups
- **Lockfile Schema v3.0**: Bumped schema to `v3.0` with `min_compatible_version: "1.0"`. Added validation rejecting obsolete or incompatible lockfile revisions.
- **Deprecated aes-gcm**: Completely purged legacy `aes-gcm` crate from dependencies and codebase.
- **`unsafe_mode` Feature Documentation**: Documented dangerous nature of `unsafe_mode` in `Cargo.toml` and `README.md`, which allows `INTERENV_UNSAFE=1` to bypass Windows Job Object process isolation strictly for headless CI environments.

Summary of fixes from the InterEnv v0.1.0 Security Audit across cryptography, process isolation, schema migration, and pre-commit protection.

### Critical Fixes
- **Argon2id Parameters ([Audit Finding 1](#1-argon2id-parameters-src-crypto-kdfrs-25))**:
  - Replaced legacy parameters with OWASP-compliant defaults: `Params::new(19 * 1024, 2, 1, Some(32))` (19 MiB memory cost, 2 iterations, parallelism = 1).
  - Added runtime memory sanity check (`check_available_memory`) that fails fast if system available memory is below 64 MiB.
- **Lockfile Schema Migration ([Audit Finding 2](#2-lockfile-schema-migration-src-envfile-lockfilers))**:
  - Upgraded lockfile version to `"2.0"` in `InterLock`.
  - Added `kdf: KdfParams` (specifying `algo`, `mem_kib`, `iterations`, `parallelism`, `version`) and `cipher: String`.
  - Decorated all fields with `#[serde(default)]` to guarantee backward compatibility with legacy v1.0 lockfiles.
- **Cipher Migration to XChaCha20-Poly1305 ([Audit Finding 3](#3-migrate-aes-256-gcm--xchacha20-poly1305-src-crypto-cipherrs))**:
  - Replaced `aes-gcm` with `chacha20poly1305` and `aead = "0.5"`.
  - Implemented authenticated encryption using 24-byte cryptographically secure random nonces sourced from `rand_core::OsRng`.
  - Deprecated legacy `aes-256-gcm` lockfiles with informative rejection instructing re-encryption under XChaCha20-Poly1305.
- **Plaintext Buffer Zeroization ([Audit Finding 4](#4-zeroize-plaintext-buffers))**:
  - Wrapped `serde_json::to_vec` serialized plaintext payloads in `Zeroizing<Vec<u8>>` within `handle_lock` and `handle_edit`.
  - Introduced `Secrets(BTreeMap<String, Zeroizing<String>>)` with a manual `Drop` and `Zeroize` implementation that actively wipes all secret values from RAM immediately upon release.
  - Replaced all post-decryption `EnvMap` instances with `Secrets` across `handle_run`, `handle_show`, `handle_edit`, `load_and_decrypt_env`, and `execute_with_env`.
- **Harden `interenv edit` Workflow ([Audit Finding 5](#5-harden-interenv-edit-src-mainrs-handle_edit))**:
  - Moved ephemeral temporary files to `std::env::temp_dir()`.
  - Enforced POSIX file permissions `0o600` via `PermissionsExt` on Unix; stripped inherited DACLs and applied owner-only security descriptors via `harden_windows_acl` on Windows.
  - Registered `ctrlc` signal handlers ensuring temporary plaintext files are wiped and unlinked upon interruption.
  - Added RAII `TempFileGuard` executing DoD 3-pass overwrite and immediate unlinking on drop / panic unwind.
  - Refused overwriting lockfiles if modified buffer parses to an empty environment map without explicit `--force`.
- **Hardened Git Pre-Commit Hook ([Audit Finding 6](#6-rewrite-the-pre-commit-hook-src-git-hookrs))**:
  - Added recursive scanning into submodules via `git submodule foreach --recursive`.
  - Scanned staged file paths null-separated with `git diff --cached --name-only -z --diff-filter=AM`.
  - Added comprehensive entropy and secret signature regex covering OpenAI, Anthropic, AWS, Stripe, GitHub, Slack, JWT, private keys, database connection strings, and SendGrid tokens.
  - Scanned staged diff content via `git diff --cached -U0`.
  - Supported git worktrees by resolving common git directories via `git rev-parse --git-common-dir` and installing forwarding hooks.
- **Project ID Derivation Stability ([Audit Finding 7](#7-compute_project_id-stability-src-mainrs-43-56))**:
  - Bound project ID derivation to directory name + `.git/HEAD` contents (if present) + manifest prefix (`Cargo.toml` or `package.json`).
  - Extended hash truncation from 12 to 16 hex characters to eliminate collisions across renames while remaining stable across working directory relocations.
- **Keyring KEK Masking ([Audit Finding 8](#8-keyring-encrypt-key-with-passphrase-derived-kek-before-storing))**:
  - Masked stored master keys with a project-bound key encryption key derived from `Sha256(project_id)` before persisting to OS credential managers.

### Medium Fixes
- **Parser Robustness & Syntax Validation ([Audit Finding 9](#9-parser-multiline--utf-8--key-validation-src-envfile-parser-rs))**:
  - Implemented multi-line quoted string parser tracking escape sequences and multiline double/single quotes across lines.
  - Validated environment variable keys against `^[A-Za-z_][A-Za-z0-9_]*$`.
  - Fixed trailing comment stripping to only trigger when preceded by whitespace outside of active quotes.
  - Updated lockfile banner header to `"# Sealed by InterEnv - https://github.com/Bharathcoorg/interenv"`.
  - Escaped tab, carriage return, newline, and backslash characters during formatting.
- **UTF-8 Safe Value Masking ([Audit Finding 10](#10-mask_value-utf-8-safety-src-mainrs-275-283))**:
  - Replaced byte-slice indexing in `mask_value` with Unicode character iterator slicing (`chars().take(3)` / `chars().rev().take(3)`), eliminating panics on multi-byte codepoints.
- **Process Runner Isolation ([Audit Finding 11](#11-process-runner-hardening-src-runner-exec-rs))**:
  - Invoked `cmd.env_clear()` before injecting secrets, retaining only a minimal whitelist of host variables (`PATH`, `SYSTEMROOT`, `HOME`, `SHELL`, `LANG`, etc.).
  - Set `libc::setsid()` on Unix child processes for process group isolation.
  - Installed Ctrl+C signal forwarding from parent to child process.
  - Connected child stdin to `Stdio::null()` when running headless (`!atty::is(Stream::Stdin)`) to prevent terminal deadlocks.
- **CI Passphrase Enforcement ([Audit Finding 12](#12-interenv_passphrase-env-var-src-enclave-fallback-rs))**:
  - Enforced that `INTERENV_PASSPHRASE` is only honored when `INTERENV_CI=1` is explicitly defined, issuing a warning on stderr and zeroizing the passphrase string immediately after KDF derivation.
- **System Diagnostics & Introspection ([Audit Finding 13](#13-display-banner--version-fix-src-mainrs-handle_status-handle_show))**:
  - Added `interenv doctor` subcommand reporting OS details, detected keyring backend, KDF parameters, default cipher, and filesystem type warnings.
  - Added `interenv version` subcommand reporting release metadata.

### Node.js SDK
- **Prebuilt Binary Distribution ([Audit Finding 14](#14-remove-cargo-fallback-from-bin-clijs))**:
  - Removed source `cargo run` fallback from `bin/cli.js`, enforcing reliance on prebuilt binaries.
  - Added `scripts/install.js` downloading platform-specific binaries during installation.
- **SDK Execution Hygiene ([Audit Finding 15](#15-node-sdk-config-env-hygiene-indexjs))**:
  - Restricted Node.js child execution environment to a sanitized whitelist of environment variables.
  - Set `INTERENV_CI=1` automatically when a passphrase is provided to allow headless execution.
  - Enforced strict path resolution on custom `binaryPath` options to prevent directory traversal.

### Section 11: Enclave & Process-Isolation Audit (Round 2)
Full findings tracked in [GitHub Issue #1](https://github.com/Bharathcoorg/interenv/issues/1).

- **Hardware KEK Binding**: Replaced software-XOR KEK paths with genuine hardware binding — macOS Secure Enclave ECIES via `security-framework` (`Token::SecureEnclave`, `ECIESEncryptionStandardX963SHA256AESGCM`); Linux TPM 2.0 seal/unseal (`create_primary` RSA-2048 restricted decryption → `create` carrying `SensitiveData = master_key` → marshall private+public → `load` + `unseal`); strict Windows NCrypt/DPAPI dispatch on `kek_id` with no silent downgrade. Master key never appears in user memory.
- **Parent-Death Cleanup**: Linux `pre_exec` now sets `PR_SET_PDEATHSIG(SIGKILL)` before `setsid()`, with a re-parent guard (`getppid != parent_pid -> _exit(1)`), and installs seccomp before `setsid()`.
- **Argon2id Parameters**: Upgraded to RFC 9106's second recommended set — 64 MiB / t=3 / p=4 — and updated `tests/kdf_params.rs`.
- **Seccomp Deny-List**: `SeccompRule::new(vec![])` returns `Err(EmptyRule)`, so the previous `if let Ok(rule)` branch was dead. `build_filter()` now maps each syscall to `vec![]` (the correct empty-rule-vector idiom) and is unit-tested (`deny_list_is_non_empty`).
- **TOCTOU-Free Canonicalization**: Unix walk now opens each component with `O_NOFOLLOW` relative to its true parent fd and resolves the canonical path from the open fd (`/proc/self/fd` on Linux), eliminating the race between per-component checks and the final name-based `canonicalize`.
- **Shredder Error Reporting**: `fallocate`/`BLKDISCARD` failures are now surfaced with warnings instead of discarded; `BLKDISCARD` ioctl (`_IO(0x12, 119) = 0x1277`) is properly invoked on block devices.
- **Project ID Entropy**: Hashes only the extracted project name + git HEAD + folder name, so secrets in manifest bytes cannot leak into the plaintext project ID.
- **Passphrase Hygiene**: Read from `INTERENV_PASSPHRASE_FILE`; when sourced from the env var it is immediately `env::remove_var`'d to prevent `/proc/$PID/environ` leakage.
- **macOS Sandbox Profile**: Now gated on `INTERENV_STRICT_SANDBOX=1` with a permissive default profile.

### Tests & Tooling
- Added property-based tests via `proptest`:
  - `tests/parser_proptest.rs`: Verified parser resilience against random strings and idempotent round-trips.
  - `tests/cipher_roundtrip.rs`: Verified variable payload sizes up to 64 KiB and nonce uniqueness across 10,000 runs.
  - `tests/shred_safety.rs`: Verified DoD overwrite and `TempFileGuard` unwinding behavior on panic.
  - `tests/edit_crash_recovery.rs`: Verified temporary file cleanup during interrupted editing.
  - `tests/hook_in_worktree.rs`: Verified git pre-commit hook behavior in linked git worktrees.
  - `tests/project_id_stability.rs`: Verified hash stability across folder renames.
  - `tests/kdf_params.rs`: Verified OWASP Argon2id compliance.
- Enabled `overflow-checks = true` in release profiles and enabled compiler warning lints for unsafe operations and missing debug implementations.

---

## [0.1.0] - 2026-09-05

### Added
- **Hardware Enclave & OS Keyring Integration**: Master key storage backed by macOS TouchID / Keychain, Windows Hello / TPM 2.0 (via DPAPI), and Linux Secret Service.
- **Argon2id Passphrase Fallback**: Memory-hard key derivation for headless CI/CD, Docker, or cross-machine project sharing.
- **AES-256-GCM AEAD Cryptographic Engine**: Authenticated encryption with 96-bit random OS nonces.
- **Memory Zeroization**: Plaintext secret buffers implement `zeroize::ZeroizeOnDrop`.
- **DoD 5220.22-M 3-Pass Shredder**: Cryptographically overwrites and destroys plaintext `.env` files from physical disk.
- **In-Memory Process Runner**: `interenv run <cmd...>` launches child processes with injected secrets directly into memory.
- **Safe Secrets Editor**: `interenv edit` securely decrypts to an ephemeral buffer and re-seals upon save.
- **Git Pre-Commit Leak Detector**: `interenv hook install` blocks accidental commits of `.env` files and API keys.
- **Node.js & TypeScript SDK**: `require('interenv').config()` with TypeScript declarations.
