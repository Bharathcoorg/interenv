# Security Policy

## Scope

InterEnv is a local secrets-management tool. The current unreleased hardening work uses XChaCha20-Poly1305 for lock payloads, Argon2id for passphrase-derived keys, hardware-backed providers where available, and operating-system credential stores as explicitly labeled fallbacks.

## Reporting a Vulnerability

Please do not open a public issue for a suspected security vulnerability.

**Security contact:** `bharathcoorg7@gmail.com`

Please include:
- affected platform and InterEnv build/commit;
- a minimal reproduction or proof of concept;
- attacker capabilities and impact;
- whether the issue affects existing lockfiles or only newly created lockfiles.

We will acknowledge reports as promptly as practical and coordinate disclosure with affected users.

## Current Security Boundaries

- **Lock payload:** XChaCha20-Poly1305 authenticated encryption.
- **Lock metadata:** schema v4 metadata is authenticated as AEAD associated data. Legacy lockfiles are accepted only to migrate them to v4.
- **Key providers:** Secure Enclave/TPM providers are used when available; OS credential-store fallbacks are labeled as such. Software-derived XOR KEKs are no longer accepted.
- **Passphrases:** Argon2id derives a 256-bit key using the lockfile's random salt and current KDF parameters.
- **Runtime isolation:** Linux seccomp, macOS Sandbox, and Windows Job Objects fail closed when their security boundary cannot be installed.
- **Lockfile writes:** staged, flushed, permission-restricted, and atomically replaced where the platform supports atomic replacement.
- **Git hooks:** existing pre-commit hooks are preserved and restored instead of silently overwritten.

## Important Limitations

InterEnv cannot guarantee that plaintext never exists anywhere outside its lockfile. A command that receives environment variables can copy, log, transmit, or persist them. Operating systems may also retain copies in process memory, swap, crash dumps, terminal buffers, filesystem snapshots, or copy-on-write storage.

The plaintext cleanup command performs best-effort overwrites and unlinking. It does **not** claim guaranteed physical erasure on SSDs, wear-leveling storage, snapshots, journaled filesystems, or copy-on-write filesystems.

A local root/kernel attacker remains outside the protection boundary.

## Release Status

This repository contains unreleased security hardening. No new package or release is implied by these source changes. Release/CI publication hardening is intentionally handled separately and must not be considered a security guarantee of the current published artifacts.
