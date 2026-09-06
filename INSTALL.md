# Installing InterEnv

InterEnv is available as a standalone compiled native binary and via package managers across major programming ecosystems.

> **Note**: Real TPM 2.0 support requires building with `--features tpm`.
> Without this flag, Linux falls back to software-based KEK protection.

---

## 1. Rust (`cargo`)

### From Crates.io
```bash
cargo install interenv
```

### With Hardware TPM 2.0 Support (Linux)
```bash
# Requires libtss2-dev installed on Ubuntu/Debian:
# sudo apt-get install -y libtss2-dev pkg-config libdbus-1-dev
cargo install interenv --features tpm
```

### From Source
```bash
git clone https://github.com/Bharathcoorg/interenv.git
cd interenv
cargo build --release --features tpm
# Binary is located at target/release/interenv
```

---

## 2. Node.js & TypeScript (`npm` / `npx`)

### Global CLI Installation
```bash
npm install -g interenv
```

### Instant Invocation via NPX
```bash
npx interenv --help
```

### In Application Projects
```bash
npm install interenv
```
```javascript
// Automatically load hardware-isolated secrets into process.env
require('interenv').config();
```

---

## 3. Python (`pip`)

```bash
pip install interenv
```
```python
from interenv import load_env
load_env()
```

---

## 4. Go (`go get`)

```bash
go get github.com/Bharathcoorg/interenv/go/interenv
```
```go
import "github.com/Bharathcoorg/interenv/go/interenv"

func main() {
    interenv.Load()
}
```

---

## 5. PHP (`composer`)

```bash
composer require bharathcoorg/interenv
```
```php
use InterEnv\InterEnv;
InterEnv::load();
```

---

## 6. Prebuilt Standalone Binaries (GitHub Releases)

Download precompiled, signed release binaries for your operating system from:
👉 **[GitHub Releases](https://github.com/Bharathcoorg/interenv/releases)**

- **Linux x86_64**: `interenv-linux-x86_64.tar.gz`
- **macOS Apple Silicon**: `interenv-darwin-aarch64.tar.gz`
- **macOS Intel**: `interenv-darwin-x86_64.tar.gz`
- **Windows x86_64**: `interenv-windows-x86_64.zip`

Extract and place `interenv` / `interenv.exe` on your system `$PATH`.

---

## 7. Container / Docker (`ghcr.io`)

```bash
docker pull ghcr.io/bharathcoorg/interenv:latest
```
