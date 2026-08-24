from __future__ import annotations

import pytest

from secret_runtime.core.policies import PolicyDocument, PolicyEngine, PolicyError, SQLitePolicyRepository
from secret_runtime.core.references import SecretReference
from secret_runtime.models import DestinationContext


def test_policy_allows_expected_host(runtime_config):
    repo = SQLitePolicyRepository(runtime_config.paths.database)
    repo.store(
        PolicyDocument.from_yaml(
            """
secret: github/prod
allow:
  hosts:
    - api.github.com
"""
        )
    )
    engine = PolicyEngine(repo)
    decision = engine.evaluate(
        secret_reference=__import__("secret_runtime").SecretReference.parse("secret://github/prod"),
        destination=DestinationContext(host="api.github.com", method="GET"),
    )
    assert decision.allowed is True


def test_policy_denies_untrusted_host(runtime_config):
    repo = SQLitePolicyRepository(runtime_config.paths.database)
    repo.store(
        PolicyDocument.from_yaml(
            """
secret: github/prod
allow:
  hosts:
    - api.github.com
deny:
  hosts:
    - "*"
"""
        )
    )
    engine = PolicyEngine(repo)
    decision = engine.evaluate(
        secret_reference=__import__("secret_runtime").SecretReference.parse("secret://github/prod"),
        destination=DestinationContext(host="attacker.com", method="POST"),
    )
    assert decision.allowed is False


def test_policy_denies_insecure_external_http_by_default(runtime_config):
    repo = SQLitePolicyRepository(runtime_config.paths.database)
    repo.store(
        PolicyDocument.from_yaml(
            """
secret: github/prod
allow:
  hosts:
    - api.github.com
"""
        )
    )
    decision = PolicyEngine(repo).evaluate(
        SecretReference.parse("secret://github/prod"),
        DestinationContext(host="api.github.com", method="GET", scheme="http"),
    )

    assert decision.allowed is False
    assert "insecure HTTP" in decision.reason


def test_policy_can_explicitly_allow_insecure_http(runtime_config):
    repo = SQLitePolicyRepository(runtime_config.paths.database)
    repo.store(
        PolicyDocument.from_yaml(
            """
secret: internal/dev
allow:
  hosts:
    - internal.example
schemes:
  - http
"""
        )
    )
    decision = PolicyEngine(repo).evaluate(
        SecretReference.parse("secret://internal/dev"),
        DestinationContext(host="internal.example", method="GET", scheme="http"),
    )

    assert decision.allowed is True


def test_policy_rejects_unknown_scheme_during_parsing():
    with pytest.raises(PolicyError, match="policy schemes must be http or https"):
        PolicyDocument.from_yaml(
            """
secret: service/prod
allow:
  hosts:
    - api.example.com
schemes:
  - ftp
"""
        )
