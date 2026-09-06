# InterEnv Security Model & Defense Architecture

This document describes the security guarantees, threat boundaries, and implementation mechanics of **InterEnv**.

---

## 1. Zero Plaintext on Disk

Traditional environment management tools write unencrypted `.env` files to physical storage, exposing secrets to:
1. Accidental git commits
2. Malicious background scripts and extensions (VS Code / Cursor / npm dependencies)
3. Undeleted temp files and backup caches
4. SSD flash wear-leveling and Copy-on-Write (CoW) disk residue

InterEnv eliminates plaintext on disk through:
- **XChaCha20-Poly1305 AEAD**: Authenticated encryption with 24-byte random CSPRNG nonces.
- **DoD 5220.22-M 3-Pass Overwrite**: Wiping plaintext with `0x00`, `0xFF`, and CSPRNG bytes.
- **Hardware-Level Decommitment**: Windows Alternate Data Stream (ADS) purging, Linux `fallocate(FALLOC_FL_PUNCH_HOLE)` + `ioctl(BLKDISCARD)`, and macOS `F_FULLFSYNC`.

---

## 2. Hardware Enclave Key Wrapping (KEK)

The 256-bit master key is never stored unencrypted on disk:

| Platform | Hardware Element | Mechanism | ID Tag |
|---|---|---|---|
| **Windows** | TPM 2.0 / Virtualization Isolation | NCrypt `MS_PLATFORM_CRYPTO_PROVIDER` + DPAPI | `windows-ncrypt-tpm-v2` |
| **macOS** | Apple Secure Enclave / TouchID | EC P-256 with `USER_PRESENCE` + ECIES AES-GCM | `macos-secure-enclave-v1` |
| **Linux** | TPM 2.0 Hardware Module | `tss-esapi` TPM2 Primary Key Binding | `linux-tpm2-v1` |
| **Headless / CI** | Memory-Hard KDF | OWASP Argon2id (19 MiB RAM, 2 iterations) | `interenv-kek-v2` |

---

## 3. In-Memory Process Isolation

When executing processes via `interenv run`:
- Environment variables are wiped to a strict whitelist before secret injection.
- **Linux**: Child processes execute under a compiled `seccomp-bpf` filter blocking `ptrace`, `process_vm_readv`, `process_vm_writev`, and `kcmp`.
- **macOS**: Installed Apple Sandbox Profile restricts unauthorized file write paths.
- **Windows**: Child processes attach to a dedicated Windows Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
- **RAM Zeroization**: Secret buffers implement `zeroize::ZeroizeOnDrop` to scrub heap memory on exit.
