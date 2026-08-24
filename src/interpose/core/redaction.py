from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass
class SecretRedactionEngine:
    _values: set[str] = field(default_factory=set)
    _fingerprints: set[str] = field(default_factory=set)

    def register(self, secret_value: str) -> str:
        fingerprint = hashlib.sha256(secret_value.encode("utf-8")).hexdigest()
        self._values.add(secret_value)
        self._fingerprints.add(fingerprint)
        return fingerprint

    def register_many(self, secrets: Iterable[str]) -> tuple[str, ...]:
        return tuple(self.register(secret) for secret in secrets)

    @property
    def fingerprints(self) -> tuple[str, ...]:
        return tuple(sorted(self._fingerprints))

    def redact(self, text: str) -> str:
        redacted = text
        for secret_value in sorted(self._values, key=len, reverse=True):
            escaped = re.escape(secret_value)
            redacted = re.sub(escaped, "[REDACTED]", redacted)
        return redacted

    def redact_bytes(self, payload: bytes) -> bytes:
        try:
            return self.redact(payload.decode("utf-8")).encode("utf-8")
        except UnicodeDecodeError:
            return payload

