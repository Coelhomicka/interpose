from __future__ import annotations

import base64

import pytest

from interpose.config import RuntimeConfig
from interpose.container import create_container


@pytest.fixture()
def runtime_config(tmp_path, monkeypatch) -> RuntimeConfig:
    home = tmp_path / "runtime"
    key = base64.urlsafe_b64encode(b"unit-test-master-key-unit-test-master-key")
    monkeypatch.setenv("INTERPOSE_HOME", str(home))
    monkeypatch.setenv("INTERPOSE_MASTER_KEY", key.decode("ascii"))
    return RuntimeConfig.from_env()


@pytest.fixture()
def runtime_container(runtime_config) :
    return create_container(runtime_config)

