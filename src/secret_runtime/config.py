from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path


def _normalize_key_material(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def _decode_key(value: str) -> bytes:
    candidate = value.strip()
    if not candidate:
        raise ValueError("SECRET_RUNTIME_MASTER_KEY cannot be empty")
    if all(ch in "0123456789abcdefABCDEF" for ch in candidate) and len(candidate) % 2 == 0:
        return bytes.fromhex(candidate)
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return candidate.encode("utf-8")


@dataclass(frozen=True)
class RuntimePaths:
    home: Path
    database: Path
    audit_database: Path
    master_key_file: Path

    @classmethod
    def from_env(cls) -> RuntimePaths:
        home = Path(os.getenv("SECRET_RUNTIME_HOME", str(Path.home() / ".secret-runtime"))).expanduser()
        return cls(
            home=home,
            database=home / "runtime.db",
            audit_database=home / "audit.db",
            master_key_file=home / "master.key",
        )


@dataclass(frozen=True)
class RuntimeConfig:
    paths: RuntimePaths
    master_key: bytes
    agent_name: str = "unknown"

    @classmethod
    def from_env(cls) -> RuntimeConfig:
        paths = RuntimePaths.from_env()
        agent_name = os.getenv("SECRET_RUNTIME_AGENT", "unknown").strip() or "unknown"
        master_key = load_master_key(paths.master_key_file)
        return cls(paths=paths, master_key=master_key, agent_name=agent_name)


def load_runtime_config() -> RuntimeConfig:
    return RuntimeConfig.from_env()


def load_master_key(master_key_file: Path) -> bytes:
    env_value = os.getenv("SECRET_RUNTIME_MASTER_KEY")
    if env_value:
        return _normalize_key_material(_decode_key(env_value))

    master_key_file.parent.mkdir(parents=True, exist_ok=True)
    if master_key_file.exists():
        return _normalize_key_material(master_key_file.read_bytes())

    generated = os.urandom(32)
    master_key_file.write_bytes(generated)
    return _normalize_key_material(generated)
