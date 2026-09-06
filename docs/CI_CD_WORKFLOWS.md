# InterEnv CI/CD & Headless Workflows

How to run InterEnv in automated CI/CD pipelines, Docker containers, and headless servers without human interactive terminal prompts.

---

## 1. The Headless Passphrase Pattern

When sealing a project for multi-developer or CI/CD usage:

```bash
# Seal using an Argon2id passphrase instead of machine-bound TPM
interenv lock --passphrase
```

In your CI environment (GitHub Actions, GitLab, Jenkins), set two environment variables:
- `INTERENV_CI=1` (forces non-interactive mode)
- `INTERENV_PASSPHRASE=<your-secret-passphrase>`

---

## 2. GitHub Actions Integration

```yaml
name: Test Application

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install InterEnv
        run: cargo install interenv --locked

      - name: Run Test Suite with Injected Secrets
        env:
          INTERENV_CI: "1"
          INTERENV_PASSPHRASE: ${{ secrets.INTERENV_VAULT_PASSPHRASE }}
        run: |
          interenv run npm test
```

---

## 3. GitLab CI Integration

```yaml
test_job:
  image: node:20
  variables:
    INTERENV_CI: "1"
    INTERENV_PASSPHRASE: "$CI_INTERENV_PASSPHRASE"
  before_script:
    - npm install -g interenv
  script:
    - interenv run npm test
```
