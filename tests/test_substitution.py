from __future__ import annotations

from secret_runtime.core.substitution import SecretSubstitutionEngine
from secret_runtime.secrets.encrypted_local import EncryptedLocalSecretStore


def test_substitution_engine_resolves_placeholder(runtime_config):
    store = EncryptedLocalSecretStore(runtime_config.paths.database, runtime_config.master_key)
    store.store("secret://github/prod", "ghp_test_123")
    engine = SecretSubstitutionEngine(store.resolve)

    result = engine.substitute("Bearer secret://github/prod")

    assert result.value == "Bearer ghp_test_123"
    assert result.references == ("secret://github/prod",)
    assert result.resolutions[0].value == "ghp_test_123"

