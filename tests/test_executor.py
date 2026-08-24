from __future__ import annotations

import subprocess

from interpose.core.audit import AuditLogger
from interpose.core.policies import PolicyDocument, PolicyEngine, SQLitePolicyRepository
from interpose.core.redaction import SecretRedactionEngine
from interpose.executor.trusted_executor import TrustedExecutor
from interpose.secrets.encrypted_local import EncryptedLocalSecretStore


def test_executor_resolves_and_redacts(runtime_config, monkeypatch):
    store = EncryptedLocalSecretStore(runtime_config.paths.database, runtime_config.master_key)
    store.store("secret://github/prod", "ghp_real_secret")
    repo = SQLitePolicyRepository(runtime_config.paths.database)
    repo.store(
        PolicyDocument.from_yaml(
            """
secret: github/prod
allow:
  hosts:
    - api.github.com
methods:
  - GET
"""
        )
    )
    executor = TrustedExecutor(
        secret_store=store,
        policy_engine=PolicyEngine(repo),
        audit_logger=AuditLogger(runtime_config.paths.audit_database),
        redaction_engine=SecretRedactionEngine(),
        agent_name="codex",
    )

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout="response contains ghp_real_secret", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    result = executor.execute(
        [
            "curl.exe",
            "https://api.github.com/user",
            "-H",
            "Authorization: Bearer secret://github/prod",
        ],
        agent="codex",
    )

    assert captured["command"][3] == "Authorization: Bearer ghp_real_secret"
    assert result.stdout == "response contains [REDACTED]"
