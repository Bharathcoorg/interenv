# InterEnv Quickstart Guide

Hardware-Enclave Protected Secrets for Terminal, Microservices, and Multi-Language Applications. Zero Plaintext `.env` on Disk. Built by **Interlayer**.

---

## 1. CLI Installation

Install the native binary globally:

```bash
# Via Cargo (Rust)
cargo install interenv

# Via NPM (Node.js)
npm install -g interenv

# Via Homebrew / Linux installer script
curl -fsSL https://raw.githubusercontent.com/Bharathcoorg/interenv/main/scripts/install.sh | bash
```

Verify installation:
```bash
interenv --version
interenv doctor
```

---

## 2. Core CLI Workflow

### Step 1: Seal your existing `.env` file into hardware
```bash
interenv lock
```
*Your plaintext `.env` is encrypted with XChaCha20-Poly1305, sealed in the OS hardware enclave (Windows TPM 2.0 / Apple Secure Enclave / Linux Secret Service), and shredded from disk using DoD 5220.22-M 3-pass overwrite.*

### Step 2: Run commands with in-memory secrets
```bash
# Secrets injected into memory — no plaintext on disk
interenv run npm start
interenv run python main.py
interenv run go run main.go
```

### Step 3: View or edit secrets safely
```bash
# Display masked secrets
interenv show

# Display unmasked secrets in terminal
interenv show --reveal

# Secure in-memory editor (shreds on exit)
interenv edit
```

---

## 3. Multi-Language SDKs

### Node.js / TypeScript
```bash
npm install interenv
```
```typescript
import { config } from "interenv";

// In-memory loading into process.env directly
config();

console.log(process.env.OPENAI_API_KEY);
```

### Python
```bash
pip install interenv
```
```python
import interenv
import os

# Direct in-memory injection into os.environ
interenv.load_env()

print(os.getenv("OPENAI_API_KEY"))
```

### Go
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
	if err := interenv.Load(); err != nil {
		panic(err)
	}
	fmt.Println(os.Getenv("OPENAI_API_KEY"))
}
```

### PHP / Laravel
```bash
composer require bharathcoorg/interenv
```
```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use InterEnv\InterEnv;

// Injects secrets into $_ENV, $_SERVER, and putenv()
InterEnv::load();

echo getenv('OPENAI_API_KEY');
```

### Rust
```toml
[dependencies]
interenv = "1.0.0"
```
```rust
use interenv::InterLock;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cwd = env::current_dir()?;
    let lockfile = InterLock::find_lockfile(&cwd)
        .ok_or("No .interenv.lock found")?;
    let lock = InterLock::load(&lockfile)?;
    println!("Project {} has {} sealed keys", lock.project_name, lock.keys_count);
    Ok(())
}
```
