# InterEnv API Reference

Complete multi-language API specification for InterEnv v1.0.0.

---

## 1. CLI Commands

| Command | Flags | Description |
|---|---|---|
| `interenv lock` | `--file <path>`, `--passphrase`, `--no-shred`, `--force` | Encrypts `.env` to `.interenv.lock` and shreds plaintext. |
| `interenv run <cmd...>` | *(arguments forwarded)* | Spawns command in isolated sandbox with secrets in memory. |
| `interenv show` | `--reveal`, `--raw`, `--json` | Displays vaulted secrets (masked, raw, or JSON format). |
| `interenv edit` | `--force` | Decrypts to temporary RAM buffer, opens in `$EDITOR`, re-seals on save. |
| `interenv hook install` | *(none)* | Installs secret-leak scanner into `.git/hooks/pre-commit`. |
| `interenv shred <file>` | *(none)* | Executes DoD 5220.22-M 3-pass file destruction. |
| `interenv doctor` | *(none)* | Inspects OS enclave, TPM, and filesystem security status. |

---

## 2. Node.js SDK (`interenv`)

```typescript
import { config } from "interenv";

interface ConfigOptions {
  binaryPath?: string; // Optional custom path to interenv binary
}

function config(options?: ConfigOptions): { parsed?: Record<string, string>; error?: Error };
```

---

## 3. Python SDK (`interenv`)

```python
import interenv

# Load all secrets into os.environ
secrets: dict[str, str] = interenv.load_env(binary_path=None, override=True)

# Alias for dotenv compatibility
interenv.config()

# Retrieve single secret without mutating os.environ
secret_val: str | None = interenv.get("API_KEY", default=None)

# Run child process with in-memory injection
exit_code: int = interenv.run(["pytest", "tests/"])
```

---

## 4. Go SDK (`github.com/Bharathcoorg/interenv/go/interenv`)

```go
package interenv

// In-memory load into os.Setenv
func Load() error

// Retrieve all secrets as map
func All() (map[string]string, error)

// Get single secret
func Get(key string) string

// Run external command with injected secrets
func Run(name string, args ...string) error
```

---

## 5. PHP SDK (`bharathcoorg/interenv`)

```php
namespace InterEnv;

class InterEnv {
    public static function load(?string $binaryPath = null, bool $override = true): array;
    public static function get(string $key, ?string $default = null): ?string;
    public static function all(): array;
}
```
