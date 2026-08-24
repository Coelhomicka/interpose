from __future__ import annotations

from interpose.core.redaction import SecretRedactionEngine


def test_redaction_engine_replaces_secret_value():
    engine = SecretRedactionEngine()
    engine.register("my-token-123")

    redacted = engine.redact("Error using token my-token-123")

    assert redacted == "Error using token [REDACTED]"

