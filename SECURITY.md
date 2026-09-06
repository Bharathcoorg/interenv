# Security Policy

## Supported Versions

| Version           | Supported          |
| ----------------- | ------------------ |
| 0.1.0 and later   | :white_check_mark: |
| < 0.1.0           | :x:                |

## Reporting a Vulnerability

The **InterEnv** project takes cryptographic and secrets security vulnerabilities seriously.

If you discover a security vulnerability or potential weakness in InterEnv's enclave key storage, cryptographic implementation, or memory zeroization, please **do not open a public GitHub issue**. Instead, submit your confidential disclosure directly to the maintainer:

📧 **Security Contact**: `bharathcoorg7@gmail.com`

### Disclosure Guidelines & SLA
- **Response SLA**: Vulnerability reports will be acknowledged within **24 hours**.
- Please include:
  - A clear description of the vulnerability and affected operating systems (macOS, Windows, Linux).
  - Steps to reproduce or a minimal proof of concept.
  - Threat vector and impact assessment.

We will coordinate a private patch and release an advisory before public disclosure.

## Threat Model (v1.0)

InterEnv protects against:
- Casual disk inspection of plaintext .env files (mitigated: encrypted at rest in OS keyring)
- Memory dump by other user-level processes (mitigated: process isolation + Job Object on Windows)
- TPM/SE key extraction (mitigated: key never leaves secure element in clear)
- Replay of lockfile across machines (mitigated: KEK is bound to local hardware)
- DoD shred bypass on SSD/CoW (mitigated: fallocate PUNCH_HOLE + ioctl BLKDISCARD + honest doctor advisory)

InterEnv does NOT protect against:
- Root/kernel-level attacker on the local machine (can read any process memory or keyring)
- Physical attack on DRAM after power-off (mitigated only via OS-level memory encryption like AMD SME/Intel TME)
- Compromised build pipeline (mitigated: reproducible builds + signed releases)
- Memory disclosure via speculative execution (Meltdown/Spectre); consider disabling HT in threat-model environments

## Reporting Vulnerabilities
Email security@interlayer.dev (or bharathcoorg7@gmail.com as fallback).
PGP key: 0xDEADBEEFCAFEBABE1234 (replace with actual key before release).
Respond within 72 hours; coordinated disclosure preferred.

