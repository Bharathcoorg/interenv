# Changelog

All notable changes to **InterEnv** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
