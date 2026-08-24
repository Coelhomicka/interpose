from __future__ import annotations

import os
import re

import pytest

from secret_runtime.session.isolation.base import IsolationError, NoIsolationBackend
from secret_runtime.session.isolation.factory import create_isolation_backend
from secret_runtime.session.profile import SessionProfile, SessionProfileError


def test_profile_requires_loopback_broker_for_windows_isolation():
    with pytest.raises(SessionProfileError, match="requires broker_url"):
        SessionProfile.from_yaml(
            """
version: 1
runtime:
  isolation:
    mode: windows-appcontainer
"""
        )


def test_profile_rejects_non_loopback_isolation_broker():
    with pytest.raises(SessionProfileError, match=re.escape("must use http://127.0.0.1")):
        SessionProfile.from_yaml(
            """
version: 1
runtime:
  isolation:
    mode: windows-appcontainer
    broker_url: http://evil.example:9876
"""
        )


def test_no_isolation_backend_is_explicit(tmp_path):
    profile = SessionProfile.from_yaml("version: 1\n")

    backend = create_isolation_backend(
        profile.runtime.isolation,
        session="test",
        runtime_home=tmp_path / "runtime",
    )

    assert isinstance(backend, NoIsolationBackend)
    assert backend.name == "none"


@pytest.mark.skipif(os.name != "nt", reason="Windows AppContainer backend")
def test_windows_firewall_rules_block_loopback_except_broker_port(tmp_path, monkeypatch):
    from secret_runtime.session.isolation.windows_appcontainer import WindowsAppContainerBackend

    profile = SessionProfile.from_yaml(
        """
version: 1
runtime:
  isolation:
    mode: windows-appcontainer
    broker_url: http://127.0.0.1:9876
"""
    )
    backend = WindowsAppContainerBackend(
        options=profile.runtime.isolation,
        session="session-1",
        runtime_home=tmp_path / "runtime",
    )
    captured = {}

    def capture_script(script, operation):
        captured["script"] = script
        captured["operation"] = operation

    monkeypatch.setattr(
        "secret_runtime.session.isolation.windows_appcontainer._run_powershell",
        capture_script,
    )

    names = backend._add_loopback_firewall_rules("S-1-15-2-1-2-3-4-5-6-7-8")

    assert len(names) == 7
    assert "-Package 'S-1-15-2-1-2-3-4-5-6-7-8'" in captured["script"]
    assert "1-9875" in captured["script"]
    assert "9877-65535" in captured["script"]
    assert "127.0.0.0/8" in captured["script"]
    assert "127.0.0.2-127.255.255.255" in captured["script"]
    assert "::1" in captured["script"]


@pytest.mark.skipif(os.name != "nt", reason="Windows AppContainer backend")
def test_windows_isolation_refuses_runtime_storage_acl(tmp_path):
    from secret_runtime.session.isolation.windows_appcontainer import WindowsAppContainerBackend

    runtime_home = tmp_path / "runtime"
    runtime_home.mkdir()
    profile = SessionProfile.from_yaml(
        """
version: 1
runtime:
  isolation:
    mode: windows-appcontainer
    broker_url: http://127.0.0.1:9876
"""
    )
    backend = WindowsAppContainerBackend(
        options=profile.runtime.isolation,
        session="session-1",
        runtime_home=runtime_home,
    )

    with pytest.raises(IsolationError, match="refusing to expose Secret Runtime storage"):
        backend._validated_path(runtime_home)
