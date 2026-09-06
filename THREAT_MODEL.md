# InterEnv Threat Model (v1.0)

This document specifies the formal threat model, security boundaries, attacker personas, and residual risks for **InterEnv** v1.0.

---

## 1. Protected Assets

| Asset | Description | Sensitivity | Primary Protection |
| :--- | :--- | :--- | :--- |
| **Master Key (256-bit)** | Symmetric key encrypting project environment variables. | **CRITICAL** | OS Keyring + TPM 2.0 / Apple Secure Enclave / DPAPI KEK. Zeroized on drop. |
| **Plaintext `.env` Data** | Decrypted key-value pairs (API tokens, database credentials). | **HIGH** | In-memory only; child environment inheritance; DoD 3-pass + platform shredding. |
| **`.interenv.lock` Metadata** | Nonces, cipher identifiers, Argon2id parameters, public key labels. | **MEDIUM** | Authenticated via Poly1305 AEAD tag; integrity verified before parse. |
| **Git Repositories & History** | Commits, tags, and worktrees in source control. | **HIGH** | Pre-commit hook prevents staging unencrypted `.env` files. |

---

## 2. Adversary Profiles

1. **Casual / Shoulder Surfer**:
   - Capabilities: Physical inspection of developer display, browsing repository file tree, checking git commit history.
   - Goals: Locate plaintext secrets stored accidentally in source code or `.env`.
   - Mitigation: `.env` is never committed; lockfile stores ciphertexts only; terminal outputs mask values by default.

2. **Malicious Local Application (Unprivileged)**:
   - Capabilities: User-space process executing alongside developer tools. Can inspect filesystem, attempt process enumeration, or read `/proc/$PID/environ`.
   - Goals: Exfiltrate active credentials or intercept spawned child variables.
   - Mitigation: Linux seccomp BPF blocks `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, and `unshare`. macOS Sandbox profile restricts filesystem write access. Windows isolates children in Job Objects with `KILL_ON_JOB_CLOSE`.

3. **Network / CI Attacker**:
   - Capabilities: Compromises continuous integration build environment or intercepts network traffic.
   - Goals: Decrypt `.interenv.lock` without authorization.
   - Mitigation: Lockfile is encrypted with XChaCha20-Poly1305. Hardware-sealed keys cannot be decrypted outside the local machine. Headless environments require OWASP-compliant Argon2id passphrases.

4. **Privileged Local Attacker (Root / Administrator)**:
   - Capabilities: Kernel privileges, direct memory inspection, driver installation, hypervisor access.
   - Mitigation Boundary: **Out of scope**. A root attacker can hook syscalls, dump kernel memory, and access hardware elements directly.

---

## 3. Trust Boundaries

```
+-------------------------------------------------------------+
|                     User Application                        |
+-------------------------------------------------------------+
                              |
    [Trust Boundary 1: Process & Environment Isolation]
                              |
+-------------------------------------------------------------+
|                  InterEnv CLI / Runtime                     |
|  - Zeroized Secrets & Keys                                  |
|  - Safe Atomic Canonicalization                             |
+-------------------------------------------------------------+
                              |
    [Trust Boundary 2: Operating System Services]
                              |
+-------------------------------------------------------------+
| OS Keyring / Credential Manager / DPAPI                     |
+-------------------------------------------------------------+
                              |
    [Trust Boundary 3: Silicon Hardware Security Module]
                              |
+-------------------------------------------------------------+
|  TPM 2.0 (Windows / Linux)  |  Apple Secure Enclave (macOS) |
+-------------------------------------------------------------+
```

---

## 4. Threat Mitigations Matrix

| Threat | Impact | InterEnv Mitigation |
| :--- | :--- | :--- |
| **Accidental Git Commit** | Credential leak in public repo | Automated git pre-commit hook aborts commits containing plaintext `.env`. |
| **Stale Temp Files on Disk** | Forensic data recovery | `TempFileGuard` executes DoD 5220.22-M 3-pass wipe + `PUNCH_HOLE`/`BLKDISCARD`/`SetFileValidData`. |
| **Process Memory Dump** | RAM scraping by peer processes | `Secrets` struct wraps keys and values in `Zeroizing`; raw string buffers wiped on drop. |
| **Symlink TOCTOU Attack** | Arbitrary file overwrite / traversal | `safe_canonicalize` rejects reparse points and paths traversing outside directory hierarchy. |
| **Cross-Machine Lock Replay** | Key reuse on foreign machine | Machine-bound hardware KEK prevents foreign host decryption without passphrase. |
| **Terminal Crash During Edit** | Orphaned plaintext in temp dir | SIGHUP, SIGTERM, and SIGINT handlers invoke emergency shredder before process exit. |

---

## 5. Residual Risks & Accepted Limitations

1. **Root Privilege Escalation**: Once an adversary achieves root or kernel ring-0 access, no user-mode tooling can protect keys or memory.
2. **Cold Boot Attacks**: Physical access to unpowered RAM immediately after system shutdown may allow recovery of in-memory data unless hardware memory encryption (AMD SME / Intel TME) is active.
3. **Hardware Enclave Key Invalidation**: Operating system reinstallation or TPM clearing invalidates local machine-bound keys. Developers must retain passphrase backups (`interenv lock --passphrase`) for disaster recovery.
4. **Copy-on-Write (CoW) Filesystems**: Flash controllers and CoW filesystems (e.g. Btrfs, APFS) may wear-level blocks. InterEnv applies filesystem-level decommit (`fallocate`, `F_FULLFSYNC`, `SetEndOfFile`) and reports doctor advisories when operating on SSD media.
