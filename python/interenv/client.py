"""
InterEnv Python Client Implementation
Direct in-memory hardware enclave secret injection.
"""

import json
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional


def find_binary_path() -> str:
    """Locate the native interenv executable."""
    is_win = sys.platform == "win32"
    exe_name = "interenv.exe" if is_win else "interenv"

    if "INTERENV_BIN" in os.environ and os.path.exists(os.environ["INTERENV_BIN"]):
        return os.environ["INTERENV_BIN"]

    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".interenv", "bin", exe_name),
        os.path.join(os.path.dirname(__file__), "..", "..", "target", "release", exe_name),
        os.path.join(os.path.dirname(__file__), "..", "..", "target", "debug", exe_name),
    ]

    for candidate in candidates:
        if os.path.exists(candidate):
            return os.path.abspath(candidate)

    # Search PATH
    which_bin = shutil.which(exe_name)
    if which_bin:
        return which_bin

    return exe_name


def _build_clean_env() -> Dict[str, str]:
    """Construct sanitized execution environment for invoking interenv."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "USERPROFILE": os.environ.get("USERPROFILE", ""),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "INTERENV_CI": "1",
    }
    for key in ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "XDG_SESSION_ID", "INTERENV_PASSPHRASE"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def load_env(binary_path: Optional[str] = None, override: bool = True) -> Dict[str, str]:
    """
    Load hardware-enclave protected secrets into os.environ directly from memory.
    Zero plaintext .env file is ever touched or created on disk.
    """
    bin_path = binary_path or find_binary_path()
    cmd = [bin_path, "show", "--reveal", "--json"]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_build_clean_env(),
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.strip() or e.stdout.strip() or "interenv failed"
        raise RuntimeError(f"InterEnv execution error: {err_msg}") from e
    except FileNotFoundError as e:
        raise RuntimeError(f"InterEnv binary not found at '{bin_path}'. Install via 'cargo install interenv' or 'npm install -g interenv'.") from e

    try:
        secrets = json.loads(proc.stdout.strip())
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse InterEnv secrets JSON: {proc.stdout}") from e

    for k, v in secrets.items():
        if override or k not in os.environ:
            os.environ[k] = str(v)

    return secrets


def config(binary_path: Optional[str] = None, override: bool = True) -> Dict[str, str]:
    """Alias for load_env() matching dotenv.config() convention."""
    return load_env(binary_path=binary_path, override=override)


def get(key: str, default: Optional[str] = None, binary_path: Optional[str] = None) -> Optional[str]:
    """Retrieve a single secret value from the vaulted lockfile without mutating os.environ."""
    secrets = load_env(binary_path=binary_path, override=False)
    return secrets.get(key, default)


def run(command: List[str], binary_path: Optional[str] = None, **kwargs) -> int:
    """Execute a child process with vaulted secrets injected directly into memory."""
    bin_path = binary_path or find_binary_path()
    full_cmd = [bin_path, "run"] + command
    return subprocess.run(full_cmd, **kwargs).returncode
