# InterEnv System Architecture (v1.0)

This document describes the architectural layout, internal modules, and security enforcement pipelines of **InterEnv**.

---

## 1. High-Level Component Topology

```
+-----------------------------------------------------------------------+
|                             Developer CLI                             |
|  (interenv lock | run | edit | show | status | doctor | hook | shred)   |
+-----------------------------------------------------------------------+
        |                                                   |
        v                                                   v
+-----------------------------+             +-------------------------------+
|        Crypto Engine        |             |        Enclave Backend        |
|  - XChaCha20-Poly1305 AEAD  |             |  - Windows: NCrypt / DPAPI    |
|  - OWASP Argon2id KDF       | <=========> |  - macOS: Apple Secure Enclave|
|  - OS CSPRNG Nonces (24-byte|             |  - Linux: TPM 2.0 / Freedesk  |
+-----------------------------+             +-------------------------------+
        |                                                   |
        v                                                   v
+-----------------------------+             +-------------------------------+
|     In-Memory Secrets       |             |         Storage Layer         |
|  - Zeroizing Wrapped Map    |             |  - `.interenv.lock` (JSON v4) |
|  - String Buffer Scrubbing  |             |  - Safe Atomic Canonicalizer  |
+-----------------------------+             +-------------------------------+
        |                                                   |
        +-------------------------+-------------------------+
                                  |
                                  v
+-----------------------------------------------------------------------+
|                           Execution Engine                            |
|  - Child Process Spawning with Sanitized Environment Whitelist        |
|  - Windows: Job Object (`KILL_ON_JOB_CLOSE`)                          |
|  - Linux: Seccomp BPF (Blocks `ptrace`, `process_vm_readv`, etc.)     |
|  - macOS: Apple Sandbox Profile (`sandbox_init`)                      |
+-----------------------------------------------------------------------+
                                  |
                                  v
+-----------------------------------------------------------------------+
|                    Shredder & Hygiene Layer                           |
|  - Best-effort multi-pass overwrite, flush, and unlink; physical erasure is not guaranteed on SSD/CoW/snapshot storage                             |
|  - Linux platform-specific cleanup where supported                  |
|  - Windows platform-specific cleanup where supported         |
|  - macOS platform-specific flushing where supported                               |
+-----------------------------------------------------------------------+
```

---

## 2. Core Architectural Layers

### 2.1 Cryptographic Layer (`src/crypto/`)
- **AEAD Cipher (`cipher.rs`)**: Exclusively utilizes **XChaCha20-Poly1305** (`chacha20poly1305 = "=0.10.1"`). Every encryption generates a unique 192-bit (24-byte) cryptographic nonce from `rand::rngs::OsRng`. Plaintext decryption verifies the 128-bit Poly1305 authentication tag prior to exposing secrets.
- **Key Derivation Function (`kdf.rs`)**: Adheres to OWASP password storage recommendations with **Argon2id** (the parameters recorded in each lockfile; current defaults are defined in `src/crypto/kdf.rs`). Validates that physical system memory exceeds 64 MiB before initiating derivation to protect against denial-of-service in constrained environments.

### 2.2 Enclave & Key Encryption Key Layer (`src/enclave/`)
- **Windows**: Primary encryption via TPM 2.0 through Cryptography Next Generation (`NCryptOpenStorageProvider`, `MS_PLATFORM_CRYPTO_PROVIDER`, `BCRYPT_AES_ALGORITHM`). Fallback to Windows DPAPI is explicitly labeled as OS credential protection, not TPM hardware.
- **macOS**: Secure Enclave hardware binding with user-presence/private-key-use access controls. Software-derived key masking is not used.
- **Linux**: Direct TPM 2.0 device integration (`/dev/tpmrm0`, `/dev/tpm0`) via `tss-esapi` primary key hashing, with an explicitly labeled OS credential-store fallback when TPM support is unavailable.

### 2.3 Storage Layer (`src/envfile/lockfile.rs`)
- **Format**: Committed `.interenv.lock` file formatted as pretty-printed JSON schema version `4.0`.
- **Fields**: Encrypted payload, 24-byte nonce hex, project identifier, Argon2id salt, KDF parameters, variable name manifest (values excluded), and `min_compatible_version`.
- **Path Resolution (`src/util/safe_canonicalize.rs`)**: Strict traversal preventing symlink and reparse-point redirection attacks.

### 2.4 Execution & Isolation Layer (`src/runner/`)
- **Process Environment Sanitization**: Strips ambient environment variables, injecting exclusively whitelisted execution variables and decrypted project secrets.
- **Platform Containment**:
  - **Linux (`linux_seccomp.rs`)**: Enforces `PR_SET_NO_NEW_PRIVS` and compiles BPF filter denying `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, and `unshare`.
  - **macOS (`macos_sandbox.rs`)**: Loads sandbox profile confining disk write operations strictly to temporary descriptors and `/dev/null`.
  - **Windows (`exec.rs`)**: Registers child processes in a Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.

### 2.5 Disk Sanitization Layer (`src/shredder/`)
- **DoD Overwrite**: Three-pass overwrite using `0x00`, `0xFF`, and CSPRNG bytes.
- **Hardware Decommit**:
  - Windows: Calls `SetFileValidData(0)` and `SetEndOfFile`, enumerating and destroying Alternate Data Streams.
  - Linux: Issues `fallocate(FALLOC_FL_PUNCH_HOLE)` and `ioctl(BLKDISCARD)`.
  - macOS: Invokes `fcntl(F_FULLFSYNC)`.

### 2.6 Git Hook Layer (`src/git/`)
- **Pre-commit Interception**: Automatically discovers `.git` directory across regular repositories, submodules, and worktrees. Installs pre-commit hook preventing staging of unencrypted `.env` files.

### 2.7 Multi-language SDK Layer
- JavaScript, Python, Go, and PHP SDKs invoke a trusted native binary.
- Bundled/local binaries are preferred.
- System `PATH` execution is opt-in via `INTERENV_ALLOW_SYSTEM_PATH=1` because the native process receives decrypted secrets.
- SDK errors do not echo decrypted stdout.
