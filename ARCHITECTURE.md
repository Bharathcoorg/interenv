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
|  - Zeroizing Wrapped Map    |             |  - `.interenv.lock` (JSON v3) |
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
|  - 3-Pass DoD 5220.22-M Overwrite Pattern                             |
|  - Linux `FALLOC_FL_PUNCH_HOLE` + `BLKDISCARD` ioctl                  |
|  - Windows `SetFileValidData` Page Decommit + ADS Stream Wipe         |
|  - macOS `F_FULLFSYNC` Controller Flush                               |
+-----------------------------------------------------------------------+
```

---

## 2. Core Architectural Layers

### 2.1 Cryptographic Layer (`src/crypto/`)
- **AEAD Cipher (`cipher.rs`)**: Exclusively utilizes **XChaCha20-Poly1305** (`chacha20poly1305 = "=0.10.1"`). Every encryption generates a unique 192-bit (24-byte) cryptographic nonce from `rand::rngs::OsRng`. Plaintext decryption verifies the 128-bit Poly1305 authentication tag prior to exposing secrets.
- **Key Derivation Function (`kdf.rs`)**: Adheres to OWASP password storage recommendations with **Argon2id** (memory cost = 19 MiB, iterations = 2, parallelism = 1). Validates that physical system memory exceeds 64 MiB before initiating derivation to protect against denial-of-service in constrained environments.

### 2.2 Enclave & Key Encryption Key Layer (`src/enclave/`)
- **Windows**: Primary encryption via TPM 2.0 through Cryptography Next Generation (`NCryptOpenStorageProvider`, `MS_PLATFORM_CRYPTO_PROVIDER`, `BCRYPT_AES_ALGORITHM`). Transparent fallback to user-level DPAPI (`CryptProtectData`) with custom entropy derived from project identifiers.
- **macOS**: Secure Enclave hardware binding with user presence ACL (`SecAccessControlCreateFlags::USER_PRESENCE`) and ECIES encryption, falling back to Keychain software masking.
- **Linux**: Direct TPM 2.0 device integration (`/dev/tpmrm0`, `/dev/tpm0`) via `tss-esapi` primary key hashing, with fallback to Desktop Secret Service (`org.freedesktop.secrets`).

### 2.3 Storage Layer (`src/envfile/lockfile.rs`)
- **Format**: Committed `.interenv.lock` file formatted as pretty-printed JSON schema version `3.0`.
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

### 2.7 Node.js SDK Layer (`scripts/install.js`, `index.js`)
- **Postinstall Detection**: Resolves platform-specific binaries across `prebuilds/{platform}-{arch}/`, `target/release/`, and `target/debug/`.
- **Fail-Fast Policy**: Non-zero exit with actionable build guidance if native binary is unavailable.
