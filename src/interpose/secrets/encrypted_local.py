from __future__ import annotations

import hashlib
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..core.references import SecretReference
from ..models import ResolvedSecret, SecretMetadata
from .base import SecretNotFound, SecretStore


def _utc_now() -> datetime:
    return datetime.now(UTC)


class EncryptedLocalSecretStore(SecretStore):
    def __init__(self, database_path: Path | str, master_key: bytes) -> None:
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._aesgcm = AESGCM(hashlib.sha256(master_key).digest())
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        try:
            # sqlite3's connection context manager governs the transaction, not the
            # handle: without the explicit close the file stays open until GC, which
            # leaks descriptors and keeps the database locked on Windows.
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reference TEXT NOT NULL UNIQUE,
                    provider TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    secret_path TEXT NOT NULL,
                    ciphertext BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def _metadata_from_row(self, row: sqlite3.Row) -> SecretMetadata:
        return SecretMetadata(
            id=row["id"],
            reference=row["reference"],
            provider=row["provider"],
            namespace=row["namespace"],
            path=row["secret_path"],
            fingerprint=row["fingerprint"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def store(self, reference: SecretReference | str, value: str) -> SecretMetadata:
        ref = reference if isinstance(reference, SecretReference) else SecretReference.parse(reference)
        now = _utc_now().isoformat()
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, value.encode("utf-8"), ref.canonical.encode("utf-8"))
        fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT id, created_at FROM secrets WHERE reference = ?",
                (ref.canonical,),
            ).fetchone()
            if existing is None:
                cursor = connection.execute(
                    """
                    INSERT INTO secrets (
                        reference, provider, namespace, secret_path,
                        ciphertext, nonce, fingerprint, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ref.canonical,
                        ref.provider,
                        ref.namespace,
                        ref.path,
                        ciphertext,
                        nonce,
                        fingerprint,
                        now,
                        now,
                    ),
                )
                secret_id = int(cursor.lastrowid)
                created_at = now
            else:
                secret_id = int(existing["id"])
                created_at = existing["created_at"]
                connection.execute(
                    """
                    UPDATE secrets
                    SET provider = ?, namespace = ?, secret_path = ?, ciphertext = ?,
                        nonce = ?, fingerprint = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        ref.provider,
                        ref.namespace,
                        ref.path,
                        ciphertext,
                        nonce,
                        fingerprint,
                        now,
                        secret_id,
                    ),
                )
            connection.commit()
        return SecretMetadata(
            id=secret_id,
            reference=ref.canonical,
            provider=ref.provider,
            namespace=ref.namespace,
            path=ref.path,
            fingerprint=fingerprint,
            created_at=datetime.fromisoformat(created_at),
            updated_at=datetime.fromisoformat(now),
        )

    def resolve(self, reference: SecretReference | str) -> ResolvedSecret:
        ref = reference if isinstance(reference, SecretReference) else SecretReference.parse(reference)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM secrets WHERE reference = ?",
                (ref.canonical,),
            ).fetchone()
        if row is None:
            raise SecretNotFound(f"secret not found: {ref.canonical}")
        metadata = self._metadata_from_row(row)
        plaintext = self._aesgcm.decrypt(
            row["nonce"],
            row["ciphertext"],
            ref.canonical.encode("utf-8"),
        ).decode("utf-8")
        return ResolvedSecret(metadata=metadata, value=plaintext)

    def delete(self, reference_or_id: SecretReference | str | int) -> bool:
        if isinstance(reference_or_id, int):
            query = "DELETE FROM secrets WHERE id = ?"
            params = (reference_or_id,)
        else:
            ref = (
                reference_or_id
                if isinstance(reference_or_id, SecretReference)
                else SecretReference.parse(reference_or_id)
            )
            query = "DELETE FROM secrets WHERE reference = ?"
            params = (ref.canonical,)
        with self._connect() as connection:
            cursor = connection.execute(query, params)
            connection.commit()
            return cursor.rowcount > 0

    def exists(self, reference: SecretReference | str) -> bool:
        ref = reference if isinstance(reference, SecretReference) else SecretReference.parse(reference)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM secrets WHERE reference = ?",
                (ref.canonical,),
            ).fetchone()
        return row is not None

    def list_metadata(self) -> list[SecretMetadata]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM secrets ORDER BY reference ASC").fetchall()
        return [self._metadata_from_row(row) for row in rows]

