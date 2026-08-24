from __future__ import annotations

from typing import Protocol

from ..core.references import SecretReference
from ..models import ResolvedSecret, SecretMetadata


class SecretStoreError(RuntimeError):
    pass


class SecretNotFound(SecretStoreError):
    pass


class SecretStore(Protocol):
    def store(self, reference: SecretReference | str, value: str) -> SecretMetadata:
        raise NotImplementedError

    def resolve(self, reference: SecretReference | str) -> ResolvedSecret:
        raise NotImplementedError

    def delete(self, reference_or_id: SecretReference | str | int) -> bool:
        raise NotImplementedError

    def exists(self, reference: SecretReference | str) -> bool:
        raise NotImplementedError

    def list_metadata(self) -> list[SecretMetadata]:
        raise NotImplementedError

