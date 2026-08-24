from __future__ import annotations

import subprocess

from interpose.session.launcher import SessionLauncher, build_session_environment
from interpose.session.profile import SessionProfile


def test_profile_normalizes_reference_bindings():
    profile = SessionProfile.from_yaml(
        """
version: 1
environment:
  API_KEY: APIChave/teste
runtime:
  http_proxy: http://127.0.0.1:9876
"""
    )

    assert profile.environment == {"API_KEY": "secret://apichave/teste"}


def test_session_environment_contains_references_not_inherited_credentials():
    profile = SessionProfile.from_yaml(
        """
version: 1
environment:
  API_KEY: secret://apichave/teste
public_environment:
  API_BASE: http://127.0.0.1:9876/proxy/api.example.com
runtime:
  http_proxy: http://127.0.0.1:9876
"""
    )
    environment = build_session_environment(
        profile,
        agent="codex",
        session="session-1",
        source={
            "PATH": "safe-path",
            "REAL_API_TOKEN": "plaintext-token",
            "INTERPOSE_MASTER_KEY": "master-key",
            "INTERPOSE_HOME": "vault-path",
        },
    )

    assert environment["API_KEY"] == "secret://apichave/teste"
    assert environment["API_BASE"] == "http://127.0.0.1:9876/proxy/api.example.com"
    assert environment["PATH"] == "safe-path"
    assert environment["HTTP_PROXY"] == "http://127.0.0.1:9876"
    assert environment["NO_PROXY"] == ""
    assert "REAL_API_TOKEN" not in environment
    assert "INTERPOSE_MASTER_KEY" not in environment
    assert "INTERPOSE_HOME" not in environment


def test_launcher_never_resolves_binding(runtime_container, monkeypatch):
    runtime_container.secret_store.store("secret://apichave/teste", "real-secret")
    profile = SessionProfile.from_yaml(
        """
version: 1
environment:
  API_KEY: secret://apichave/teste
"""
    )
    launcher = SessionLauncher(
        secret_store=runtime_container.secret_store,
        audit_logger=runtime_container.audit_logger,
        runtime_home=runtime_container.config.paths.home,
    )
    captured = {}

    def fail_if_resolved(reference):
        raise AssertionError(f"resolve must not be called during launch: {reference}")

    def fake_run(command, **kwargs):
        captured["environment"] = kwargs["env"]
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(runtime_container.secret_store, "resolve", fail_if_resolved)
    monkeypatch.setattr("subprocess.run", fake_run)

    return_code = launcher.run(["agent"], profile=profile, agent="codex", session="session-1")

    assert return_code == 0
    assert captured["environment"]["API_KEY"] == "secret://apichave/teste"
