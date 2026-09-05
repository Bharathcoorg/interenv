# Contributing to InterEnv

Thank you for your interest in contributing to **InterEnv**! We welcome bug reports, feature suggestions, documentation improvements, and pull requests.

---

## 🛠️ Development Setup

### Prerequisites
- **Rust toolchain** (1.75+): [rustup.rs](https://rustup.rs/)
- **Node.js** (18+): For testing NPM packaging and TypeScript bindings
- **Git**

### Clone & Build
```bash
git clone https://github.com/Bharathcoorg/interenv.git
cd interenv

# Build debug binary
cargo build

# Run unit and integration tests
cargo test

# Run lints and formatting
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

---

## 📐 Code Guidelines
- **Zero Plaintext on Disk**: Any contribution handling secrets must ensure decrypted buffers never touch storage and implement `zeroize::ZeroizeOnDrop`.
- **Cross-Platform Compatibility**: Test that changes build cleanly across Windows, macOS, and Linux.
- **Commit Messages**: Follow [Conventional Commits](https://www.conventionalcommits.org/):
  - `feat: ...` for new features
  - `fix: ...` for bug fixes
  - `docs: ...` for documentation
  - `test: ...` for tests

---

## 🚀 Submitting a Pull Request
1. Fork the repository on GitHub.
2. Create your feature branch: `git checkout -b feat/my-feature`.
3. Commit your changes with conventional messages.
4. Push to your branch and open a Pull Request against `main`.
