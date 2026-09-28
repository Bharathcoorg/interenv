# InterEnv Threat Model

This document describes the security model of the current unreleased hardening branch. It is intentionally conservative: implementation guarantees are separated from residual risks.

## Protected Assets

| Asset | Protection |
| --- | --- |
| Master key | Hardware-backed provider where available, OS credential store fallback, or Argon2id passphrase mode |
| Environment values | XChaCha20-Poly1305 encrypted lock payload |
| Lock metadata | Authenticated as AEAD associated data in schema v4 |
| Plaintext edit buffer | Restricted temporary file, cleanup guard, best-effort overwrite/unlink |
| Git working tree | Developer-side pre-commit leak detection; not a server-side security boundary |

## Key Provider Model

### macOS
Secure Enclave is attempted for the hardware-backed path. If unavailable, InterEnv stores the master key in the macOS OS credential store and labels the lock as an OS-keyring provider. The previous deterministic/XOR software KEK fallback is rejected.

### Windows
The Microsoft Platform Crypto Provider/NCrypt path is used when available. DPAPI is treated as an OS protection mechanism, not as TPM hardware. The provider identifier reflects that distinction.

### Linux
TPM sealing requires the `tpm` feature and usable TPM hardware. If unavailable, InterEnv uses the OS credential store when available. It does not derive a KEK from public project metadata.

### Passphrase mode
Passphrase mode derives a 256-bit key using Argon2id and a random per-lock salt. This is the portability/recovery path for headless systems and machine migration.

## Lockfile Integrity

Schema v4 authenticates security-relevant metadata including:
- project identity;
- provider;
- KDF parameters and salt;
- cipher;
- key count and redacted key-name identifiers;
- creation metadata.

Changing authenticated metadata causes payload authentication to fail.

Older lockfiles use the legacy payload format and therefore cannot retroactively gain metadata authentication. They are decrypted only for migration and are immediately rewritten as v4; users should re-lock projects after upgrading.

## Runtime Isolation

### Linux
The child receives `PR_SET_NO_NEW_PRIVS` and a seccomp filter denying process inspection and namespace/kernel-control primitives including ptrace, process_vm_readv/writev, kcmp, unshare, setns, mount, umount2, pivot_root, bpf, perf_event_open, userfaultfd, and module-loading operations.

Seccomp is a syscall boundary, not a complete memory-security boundary. Files, sockets, inherited resources, and application-level exfiltration remain possible.

### macOS
The restrictive Sandbox profile is mandatory for secret-bearing commands. It denies the broad filesystem/network/IPC permissions used by the old default profile. Sandbox installation failure aborts execution.

### Windows
The child must be placed in a Job Object configured with `KILL_ON_JOB_CLOSE`. Creation, configuration, process opening, and assignment failures abort execution. There is no environment-variable bypass.

## Git Hook Boundary

The pre-commit hook is a developer convenience and leak detector. Git explicitly permits local pre-commit hooks to be bypassed with `--no-verify`, so repository/server-side controls are still required for organizational enforcement.

InterEnv preserves an existing hook by backing it up before installation and restores it during uninstall.

## Plaintext and Destruction Limits

Zeroization reduces lifetime of managed plaintext in Rust memory but cannot guarantee removal of every copy created by the OS, shell, target application, allocator, crash reporter, swap subsystem, or kernel.

The shredder performs multiple overwrites, flushes where supported, and unlinking. It does not promise physical erasure from SSDs, snapshots, journaling, copy-on-write filesystems, or wear-leveled media.

## Out of Scope

- root/kernel/hypervisor compromise;
- malicious firmware or compromised hardware;
- a command intentionally exfiltrating its own environment;
- secrets already committed to Git history;
- compromise of external package registries or published artifacts.

## Deferred Release/CI Controls

The current source hardening intentionally does not modify or execute the release/CI workflows. Therefore release signing, SBOM generation, artifact verification, and publication gates must be treated as a separate hardening task before making new security claims about published artifacts.
