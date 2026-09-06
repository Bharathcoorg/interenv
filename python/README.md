# InterEnv Python SDK

Hardware-Enclave Protected Secrets for Python & AI Agents (Zero Plaintext `.env` on Disk). Built by **Interlayer**.

## Installation

```bash
pip install interenv
```

Ensure the `interenv` native CLI is available on your system (`cargo install interenv` or `npm install -g interenv`).

## Quickstart

```python
import interenv
import os

# Seamless in-memory injection into os.environ (zero disk writes)
interenv.load_env()

api_key = os.getenv("OPENAI_API_KEY")
print("Secrets loaded safely in memory!")
```

## Programmatic Access

```python
import interenv

# Retrieve specific secret directly
db_url = interenv.get("DATABASE_URL")

# Execute a child process protected under InterEnv runner
interenv.run(["pytest", "tests/"])
```
