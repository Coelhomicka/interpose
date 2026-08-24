from __future__ import annotations

import base64

import pytest

from secret_runtime.config import RuntimeConfig
from secret_runtime.container import create_container


@pytest.fixture()
def runtime_config(tmp_path, monkeypatch) -> RuntimeConfig:
    home = tmp_path / "runtime"
    key = base64.urlsafe_b64encode(b"unit-test-master-key-unit-test-master-key")
    monkeypatch.setenv("SECRET_RUNTIME_HOME", str(home))
    monkeypatch.setenv("SECRET_RUNTIME_MASTER_KEY", key.decode("ascii"))
    return RuntimeConfig.from_env()


@pytest.fixture()
def runtime_container(runtime_config) :
    return create_container(runtime_config)

