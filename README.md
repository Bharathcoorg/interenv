<div align="center">

# 🛡️ InterEnv

### *Hardware-Enclave Protected Secrets for Terminal & Git*
**Eradicate Plaintext `.env` Files from Developer Disks Forever**

[![Crates.io](https://img.shields.io/crates/v/interenv.svg?style=flat-square&color=black)](https://crates.io/crates/interenv)
[![NPM Version](https://img.shields.io/npm/v/interenv.svg?style=flat-square&color=black)](https://www.npmjs.com/package/interenv)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Built by Interlayer](https://img.shields.io/badge/Interlayer-Ecosystem-purple.svg?style=flat-square)](https://github.com/Bharathcoorg)

<p align="center">
  <b>Built for macOS TouchID, Windows Hello / TPM 2.0, and Linux Secret Service.</b><br>
  Secrets decrypt <i>only</i> in volatile process memory. Never touches disk. Never leaks in Git.
</p>

</div>

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
1. Generates an AES-256-GCM project key and binds it to your **Hardware Enclave (TouchID / TPM / Windows Hello)**.
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
interenv run interenv edit
# Or:
interenv edit
```
Opens your default `$EDITOR` in a secure temporary buffer, updates keys, re-encrypts into `.interenv.lock`, and securely shreds the temp buffer.

### 4. Install Git Pre-Commit Protection
```bash
interenv hook install
```
Installs an automated guard in `.git/hooks/pre-commit` that detects and immediately aborts any accidental staging or commit of `.env` files or hardcoded API keys.

---

## 💻 Node.js Programmatic SDK

You can also use InterEnv directly inside your Node.js or TypeScript code:

```javascript
// At the top of your entrypoint:
require("interenv").config();

// Secrets are loaded directly into process.env without touching disk!
console.log(process.env.OPENAI_API_KEY);
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
| `interenv hook install` | Install Git pre-commit hook to prevent secret leaks |
| `interenv shred <file>` | Securely erase any file with 3-pass DoD overwrite |

---

## 🔒 Security Model

1. **Authenticated Encryption (AEAD)**: All environment payloads are encrypted with **AES-256-GCM** using 96-bit cryptographically random nonces from the OS RNG (`rand::rngs::OsRng`).
2. **Hardware Enclave Sealing**: Master encryption keys are stored directly in the host OS credential enclave:
   * **macOS**: Apple Keychain backed by Apple Secure Enclave & TouchID.
   * **Windows**: Windows Credential Manager protected by TPM 2.0 and Windows Data Protection (DPAPI).
   * **Linux**: FreeDesktop Secret Service / TPM2.
3. **Headless & CI/CD Support**: For automated CI runners and Docker containers, pass `--passphrase` or set `INTERENV_PASSPHRASE` to derive master keys via **Argon2id** (memory-hard password hashing).
4. **Memory Zeroization**: Plaintext secret buffers implement `zeroize::ZeroizeOnDrop`, ensuring sensitive keys are scrubbed from RAM as soon as they go out of scope.

---

## 🤝 Part of the Interlayer Ecosystem

InterEnv is proudly built and maintained by **Bharath B R** as part of the **Interlayer** developer tooling suite:
* [**`intermcp`**](https://github.com/Bharathcoorg/intermcp) — Ultra-fast, zero-dependency Model Context Protocol (MCP) engine and multiplexing hub in pure Rust.
* [**`interenv`**](https://github.com/Bharathcoorg/interenv) — Hardware-enclave protected secrets for terminal & git.

---

## 📄 License

MIT License. Copyright (c) 2026 Bharath B R (Interlayer).
Contributions welcome! Please open an issue or PR.
