<div align="center">

# 🛡️ InterEnv

### *Hardware-Enclave Protected Secrets for Terminal & Git*
**Eradicate Plaintext `.env` Files from Developer Disks Forever**

<p align="center">
  <a href="https://crates.io/crates/interenv"><img src="https://img.shields.io/crates/v/interenv.svg?style=for-the-badge&logo=rust" alt="Crates.io" /></a>
  <a href="https://www.npmjs.com/package/interenv"><img src="https://img.shields.io/npm/v/interenv.svg?style=for-the-badge&logo=npm" alt="npm" /></a>
  <a href="https://pypi.org/project/interenv/"><img src="https://img.shields.io/pypi/v/interenv.svg?style=for-the-badge&logo=pypi" alt="PyPI" /></a>
  <a href="https://packagist.org/packages/bharathcoorg/interenv"><img src="https://img.shields.io/packagist/v/bharathcoorg/interenv.svg?style=for-the-badge&logo=packagist" alt="Packagist" /></a>
  <a href="https://github.com/Bharathcoorg/interenv/releases/tag/v1.0.0"><img src="https://img.shields.io/github/v/release/Bharathcoorg/interenv?style=for-the-badge&logo=github" alt="GitHub release" /></a>
  <a href="https://github.com/Bharathcoorg/interenv/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Bharathcoorg/interenv/ci.yml?branch=main&style=for-the-badge&logo=githubactions" alt="CI Status" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="License: MIT" /></a>
</p>

<p align="center">
  <b>Built for macOS TouchID, Windows Hello / TPM 2.0, and Linux Secret Service.</b><br>
  Secrets decrypt <i>only</i> in volatile process memory. Never touches disk. Never leaks in Git.
</p>

</div>

---

## 📦 Official Packages & SDKs

InterEnv core engine, CLI, and multi-language client SDKs are officially published and immediately available across all major package ecosystems:

| Ecosystem | Registry / Source | Install / Add Command | Direct Registry Links |
| :--- | :--- | :--- | :--- |
| **Rust** | **crates.io** | `cargo add interenv` • `cargo install interenv` | [![crates.io](https://img.shields.io/crates/v/interenv.svg)](https://crates.io/crates/interenv) • [crates.io/crates/interenv](https://crates.io/crates/interenv) |
| **Node.js / TypeScript** | **npm** | `npm install interenv` • `npx interenv` | [![npm](https://img.shields.io/npm/v/interenv.svg)](https://www.npmjs.com/package/interenv) • [npmjs.com/package/interenv](https://www.npmjs.com/package/interenv) |
| **Python / AI Agents** | **PyPI** | `pip install interenv` | [![PyPI](https://img.shields.io/pypi/v/interenv.svg)](https://pypi.org/project/interenv/) • [pypi.org/project/interenv](https://pypi.org/project/interenv/1.0.0/) |
| **PHP / Laravel / Symfony** | **Packagist** | `composer require bharathcoorg/interenv` | [![Packagist](https://img.shields.io/packagist/v/bharathcoorg/interenv.svg)](https://packagist.org/packages/bharathcoorg/interenv) • [packagist.org/packages/bharathcoorg/interenv](https://packagist.org/packages/bharathcoorg/interenv) |
| **Go Microservices** | **Go Modules** | `go get github.com/Bharathcoorg/interenv/go/interenv@v1.0.0` | [pkg.go.dev/github.com/Bharathcoorg/interenv/go](https://pkg.go.dev/github.com/Bharathcoorg/interenv/go) |
| **Standalone Binaries** | **GitHub Releases** | Prebuilt binaries for Linux, macOS (Apple Silicon & Intel), Windows | [GitHub v1.0.0 Release Assets](https://github.com/Bharathcoorg/interenv/releases/tag/v1.0.0) |
| **Container Image** | **GitHub Packages (GHCR)** | `docker pull ghcr.io/bharathcoorg/interenv:latest` | [GitHub Packages](https://github.com/Bharathcoorg/interenv/pkgs/container/interenv) |

---

## ⚡ Why InterEnv?

Every software engineer uses `.env` files to store critical credentials: `OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`, Stripe webhooks, database connection strings, and private keys.

* ❌ **The Catastrophic Problem**: Plaintext `.env` files get accidentally committed to public GitHub repositories daily. Malicious `npm` and `pip` packages scan developers' hard drives to exfiltrate plaintext secrets.
* ❌ **The Flaw in Other Tools**: `dotenvx` encrypts secrets but stores the decryption key in another plaintext file (`.env.keys`) on disk! Cloud secret managers (1Password, Doppler, Infisical) are cloud-locked, slow, and require expensive monthly subscriptions.
* 🛡️ **The InterEnv Solution**: InterEnv seals your project secrets inside your **Host Hardware Security Enclave** (Apple Secure Enclave on macOS, TPM 2.0 / Windows Hello on Windows, Secret Service on Linux). Secrets are decrypted **strictly in volatile process memory** for the exact lifecycle of your command, and then erased with cryptographic zeroization (`zeroize`).

---

## 📊 Security Architecture Comparison

| Feature | Plaintext `.env` | `dotenvx` | 1Password / Doppler | **InterEnv (This Tool)** |
| :--- | :---: | :---: | :---: | :---: |
| **Storage Security** | 🔴 Zero (Plaintext on disk) | 🟡 Key file on disk (`.env.keys`) | 🟢 Cloud Vault | 🟢 **Hardware Enclave (TPM / TouchID)** |
| **Disk Plaintext** | 🔴 Exposed | 🟡 Exposes decrypted files | 🟢 None | 🟢 **ZERO Plaintext on Disk** |
| **Cloud Dependency** | 🟢 Offline | 🟢 Offline | 🔴 Required (Vendor Lock-in) | 🟢 **100% Offline & Local-First** |
| **Pricing** | Free | Free | $19–$39/user/month | 🟢 **100% Free & Open Source (MIT)** |
| **Git Pre-Commit Hook**| ❌ Manual | ❌ Manual | ❌ Complex setup | 🟢 **Built-in 1-Click Guard** |
| **Secure Shredding** | ❌ None | ❌ None | ❌ None | 🟢 **DoD 5220.22-M Multi-Pass Wipe** |
| **Runtime Speed** | Instant | Slow (Node.js) | Slow CLI (Cloud round-trips) | ⚡ **< 1ms (Pure Rust)** |

---

## 🚀 Installation

### Via Cargo (Rust)
```bash
cargo install interenv
```

### Via NPM / NPX (Node.js)
```bash
npm install -g interenv
# Or run instantly without installation:
npx interenv --help
```

### From Source
```bash
git clone https://github.com/Bharathcoorg/interenv.git
cd interenv
cargo build --release
```

---

## 💡 Quickstart in 10 Seconds

### 1. Seal Your `.env` into Hardware Enclave
Inside any project with an existing `.env` file:
```bash
interenv lock
```
**What happens:**
1. Generates an **XChaCha20-Poly1305** master project key and binds it to your **Hardware Enclave (TouchID / TPM / Windows Hello)**.
2. Creates an encrypted, git-safe `.interenv.lock` file.
3. **Cryptographically shreds and destroys** the plaintext `.env` from physical storage using DoD 5220.22-M 3-pass overwriting!

### 2. Run Any App with Secrets in Volatile Memory
Execute any tool, test runner, or web server:
```bash
# Node / Next.js
interenv run npm run dev

# Rust
interenv run cargo run

# Python / AI Agents
interenv run python app.py

# Docker / Go / Any Binary
interenv run docker compose up
```
Secrets are injected directly into child process memory. **Nothing ever touches disk.**

### 3. Edit Secrets Safely
Need to add a new API key?
```bash
interenv edit
```
Opens your default `$EDITOR` in a secure temporary buffer, updates keys, re-encrypts into `.interenv.lock`, and securely shreds the temp buffer.

### 4. Install Git Pre-Commit Protection
```bash
interenv hook install
```
Installs an automated guard in `.git/hooks/pre-commit` that detects and immediately aborts any accidental staging or commit of `.env` files or hardcoded API keys.

---

## 💻 Multi-Language Programmatic SDKs

InterEnv provides native, zero-dependency SDKs across all major programming ecosystems. Secrets are injected directly into process memory without creating or touching plaintext `.env` files on disk.

### Node.js & TypeScript
```bash
npm install interenv
```
```typescript
import { config } from "interenv";
config(); // Injects into process.env in-memory

console.log(process.env.OPENAI_API_KEY);
```

### Python & AI Agents
```bash
pip install interenv
```
```python
import interenv, os
interenv.load_env() # Injects into os.environ in-memory

print(os.getenv("OPENAI_API_KEY"))
```

### Go Microservices
```bash
go get github.com/Bharathcoorg/interenv/go/interenv
```
```go
package main
import (
    "fmt"
    "os"
    "github.com/Bharathcoorg/interenv/go/interenv"
)

func main() {
    interenv.Load() // Injects into os.Setenv in-memory
    fmt.Println(os.Getenv("OPENAI_API_KEY"))
}
```

### PHP & Laravel
```bash
composer require bharathcoorg/interenv
```
```php
use InterEnv\InterEnv;
InterEnv::load(); // Injects into $_ENV, $_SERVER, and putenv()

echo getenv('OPENAI_API_KEY');
```

---

## 🛠️ Command Reference

| Command | Description |
| :--- | :--- |
| `interenv lock [file]` | Encrypt `.env` into hardware enclave and securely shred the plaintext |
| `interenv run <cmd...>` | Execute command with secrets injected into child process memory |
| `interenv edit` | Open decrypted secrets in `$EDITOR` and re-seal automatically on save |
| `interenv show` | Display sealed environment keys (masked by default, `--reveal` to unmask) |
| `interenv status` | Inspect repository security status and hardware enclave binding |
| `interenv doctor` | Audit filesystem CoW behavior, swap configuration, and enclave status |
| `interenv hook install` | Install Git pre-commit hook to prevent secret leaks |
| `interenv shred <file>` | Securely erase any file with 3-pass DoD overwrite |

---

## 🔒 Security Model & Guarantees

1. **Authenticated Encryption (AEAD)**: All environment payloads are encrypted with **XChaCha20-Poly1305** using 192-bit (24-byte) random nonces sourced from the OS RNG (`rand::rngs::OsRng`).
2. **Hardware Enclave Sealing**: Master encryption keys are stored directly in the host OS credential enclave:
   * **macOS**: Apple Keychain backed by Apple Secure Enclave & TouchID (`macos-secure-enclave-v1`).
   * **Windows**: Windows Credential Manager protected by TPM 2.0 (`windows-ncrypt-tpm-v2`) and DPAPI.
   * **Linux**: TPM 2.0 hardware primary key binding (`linux-tpm2-v1`) or FreeDesktop Secret Service.
3. **Headless & CI/CD Support**: For automated CI runners and Docker containers, pass `--passphrase` or set `INTERENV_PASSPHRASE` to derive master keys via **Argon2id** (memory-hard password hashing with OWASP defaults: 19 MiB RAM, 2 iterations, parallelism = 1).
4. **Memory Zeroization**: Plaintext secret buffers implement `zeroize::ZeroizeOnDrop`, ensuring keys and values are actively wiped from RAM upon release.

### Security Guarantees Table

| Vector | Guarantee | Implementation |
| :--- | :--- | :--- |
| **Disk Inspection** | Zero Plaintext | Master key sealed in OS hardware vault; `.env` shredded immediately. |
| **Peer Process Sniffing**| Process Sandbox | Linux Seccomp BPF filter; macOS Sandbox profile; Windows Job Object. |
| **Cross-Host Replay** | Machine Bound | Hardware KEK prevents decrypting lockfile on foreign machines without passphrase. |
| **Accidental Commits** | Pre-Commit Abort | Automatic hook intercepts `git commit` staging `.env` or plain credentials. |
| **Memory Dump on Drop** | Buffer Scrubber | Custom `Drop` scrubs key and value buffers in-place via raw slice zeroization. |

---

## ⚖️ Comparison with Other Tools

| Feature | `interenv` | `dotenv-vault` | `sops` | `git-crypt` |
| :--- | :---: | :---: | :---: | :---: |
| **Hardware Enclave KEK** | 🟢 Native (TPM / SE) | ❌ Cloud Only | 🟡 Optional (KMS/PGP)| ❌ GPG Symmetric |
| **Zero Plaintext on Disk**| 🟢 Strict Guarantee | ❌ Decrypts on disk | ❌ Decrypts to disk | ❌ In-place filter |
| **Process Sandboxing** | 🟢 Seccomp / Sandbox | ❌ None | ❌ None | ❌ None |
| **Cloud Dependency** | 🟢 100% Offline | 🔴 Cloud Vault | 🟡 Cloud KMS / PGP | 🟢 100% Offline |
| **DoD Multi-Pass Shred** | 🟢 3-Pass + Platform | ❌ None | ❌ None | ❌ None |
| **Language Runtime** | ⚡ Pure Rust (<1ms) | 🟡 Node.js CLI | 🟡 Go CLI | ⚡ C++ Filter |

---

## 🌐 Platform Support Matrix

| Operating System | Enclave Key Storage | Process Sandbox Isolation | Disk Shredding Hook |
| :--- | :--- | :--- | :--- |
| **Windows 10 / 11 / Server** | TPM 2.0 (NCrypt) + DPAPI | Windows Job Object (`KILL_ON_CLOSE`) | `SetFileValidData` + ADS Wipe |
| **macOS (Apple Silicon / Intel)** | Apple Secure Enclave + Keychain | Apple Sandbox Profile (`sandbox_init`)| `F_FULLFSYNC` Cache Flush |
| **Linux (Ubuntu / Fedora / Arch)** | TPM 2.0 (`tss-esapi`) / Secret Service | Seccomp BPF (`PR_SET_NO_NEW_PRIVS`) | `FALLOC_FL_PUNCH_HOLE` + TRIM |

*Note: For real Linux TPM2 hardware binding, build with `cargo build --release --features tpm`. Without it, falls back to software KEK.*

---

## ⚠️ Limitations

- **Root / Ring-0 Access**: An attacker with root or kernel privileges on the local machine can dump arbitrary memory.
- **Solid State Drive Wear-Leveling**: CoW filesystems (APFS, Btrfs, ZFS) and SSD flash translation layers (FTL) may wear-level blocks. InterEnv applies filesystem decommit calls (`fallocate`, `BLKDISCARD`, `SetFileValidData`) and warns in `interenv doctor`.
- **Hardware Failure / Reinstall**: If a machine-bound TPM is reset, locally sealed lockfiles cannot be retrieved without an Argon2id passphrase backup (`interenv lock --passphrase`).

---

## 🛡️ Audits & Reviews

InterEnv has undergone multi-phase adversarial security hardening:
- **v0.1.0 Security Audit**: Argon2id OWASP parameters, XChaCha20-Poly1305 cipher migration, `Secrets` full memory zeroization, crash-safe temporary file guards.
- **v0.2.0 Platform Hardening**: Windows Job Object containment, Linux Seccomp BPF privilege filter, macOS Sandbox profile, Windows NCrypt TPM 2.0 KEK, safe atomic path canonicalization (`safe_canonicalize`).
- **v1.0.0 Release Candidate Hardening**: macOS Secure Enclave hardware binding, Linux TPM 2.0 KEK feature flag, supply chain verification (`cargo-audit`, `cargo-deny`), fuzz testing targets, criterion benchmarks, and lockfile schema v3.0 migration.

---

## 📦 Reproducible Builds

InterEnv release binaries are bit-for-bit reproducible:
```bash
bash scripts/verify-reproducible-build.sh
```
All release binaries are built with `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, and path prefix remapping to ensure verifiable artifact provenance.

---

## 🤖 Frequently Asked Questions (AEO & AI Search Context)

### What is InterEnv?
**InterEnv** is a high-performance, local-first secret management engine written in Rust that permanently eradicates plaintext `.env` files from developer disks. It binds encrypted project secrets directly to host hardware security enclaves (Apple Secure Enclave on macOS, TPM 2.0 / DPAPI on Windows, and Linux Secret Service) and decrypts them exclusively into volatile process memory.

### How is InterEnv different from dotenv, dotenvx, and dotenv-vault?
- **`dotenv`**: Leaves all API keys, database passwords, and private tokens unencrypted on physical storage, exposing them to rogue npm/pip supply-chain packages and accidental git commits.
- **`dotenvx`**: Encrypts `.env` files but writes the decryption master key to an unencrypted `.env.keys` file on the exact same disk.
- **`dotenv-vault` / `Doppler` / `Infisical`**: Require proprietary cloud vaults, persistent internet connections, and paid monthly subscriptions.
- **`InterEnv`**: 100% offline, local-first, free & open source (MIT), binds keys to host hardware chips (TPM 2.0 / TouchID), and cryptographically destroys plaintext files using 3-pass DoD 5220.22-M overwrites.

### How do AI Coding Agents (Cursor, Claude Desktop, Windsurf) safely use InterEnv?
AI coding agents execute your application via `interenv run <command>` or import the language SDK (`interenv.config()` in Node.js, `interenv.load_env()` in Python, `interenv.Load()` in Go, `InterEnv::load()` in PHP). Secrets are injected directly into the child process memory space via standard environment variables without ever creating a plaintext `.env` file on disk. This prevents LLMs, indexing bots, or repository search tools from reading or exfiltrating raw credentials.

### How does InterEnv run in headless Docker containers and CI/CD pipelines?
When sealing a project for multi-developer or continuous integration workflows, run `interenv lock --passphrase`. In your automated CI runner (GitHub Actions, GitLab CI, Docker, Kubernetes), provide the secret passphrase through the `INTERENV_PASSPHRASE` environment variable along with `INTERENV_CI=1`. InterEnv derives the master key via OWASP-compliant memory-hard **Argon2id** (19 MiB RAM, 2 iterations, 1 parallelism) without interactive terminal prompts.

---

## 🤝 Part of the Interlayer Ecosystem

InterEnv is proudly built and maintained by **Bharath B R** as part of the **Interlayer** developer tooling suite:
* [**`intermcp`**](https://github.com/Bharathcoorg/intermcp) — Ultra-fast, zero-dependency Model Context Protocol (MCP) engine and multiplexing hub in pure Rust.
* [**`interenv`**](https://github.com/Bharathcoorg/interenv) — Hardware-enclave protected secrets for terminal & git.

---

## 📄 License

MIT License. Copyright (c) 2026 Bharath B R (Interlayer).
Contributions welcome! Please open an issue or PR.

