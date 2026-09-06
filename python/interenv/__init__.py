"""
InterEnv Python SDK v1.0.1
Hardware-Enclave Protected Secrets for Python & AI Agents (Zero Plaintext .env on Disk)
Built by Interlayer
"""

from .client import load_env, config, get, run

__all__ = ["load_env", "config", "get", "run"]
__version__ = "1.0.1"
