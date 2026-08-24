from __future__ import annotations

from pathlib import Path

from interpose.secrets.encrypted_local import EncryptedLocalSecretStore


def test_storage_does_not_persist_plaintext(runtime_config):
    store = EncryptedLocalSecretStore(runtime_config.paths.database, runtime_config.master_key)
    store.store("secret://github/prod", "plain-secret-123")

    raw_bytes = Path(runtime_config.paths.database).read_bytes()
    assert b"plain-secret-123" not in raw_bytes

