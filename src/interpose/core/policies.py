from __future__ import annotations

import fnmatch
import ipaddress
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

from ..models import DestinationContext, PolicyDecision, PolicyRecord
from .references import SecretReference, normalize_secret_reference


class PolicyError(ValueError):
    pass


class HostGroup(BaseModel):
    hosts: list[str] = Field(default_factory=list)


class PolicyDocument(BaseModel):
    secret: str = Field(min_length=1)
    allow: HostGroup | None = None
    deny: HostGroup | None = None
    methods: list[str] | None = None
    schemes: list[str] | None = None

    @field_validator("schemes")
    @classmethod
    def validate_schemes(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        normalized = [scheme.lower() for scheme in values]
        if any(scheme not in {"http", "https"} for scheme in normalized):
            raise ValueError("policy schemes must be http or https")
        return normalized

    @classmethod
    def from_yaml(cls, source: str) -> PolicyDocument:
        try:
            payload = yaml.safe_load(source)
        except Exception as exc:  # pragma: no cover - defensive
            raise PolicyError(f"invalid policy yaml: {exc}") from exc
        if not isinstance(payload, dict):
            raise PolicyError("policy document must be a mapping")
        try:
            return cls.model_validate(payload)
        except ValidationError as exc:
            raise PolicyError(str(exc)) from exc

    def normalized_methods(self) -> tuple[str, ...]:
        return tuple(method.upper() for method in (self.methods or []))

    def normalized_secret(self) -> str:
        return normalize_secret_reference(self.secret)

    def normalized_schemes(self) -> tuple[str, ...]:
        return tuple(self.schemes or [])


def _is_loopback_destination(host: str) -> bool:
    try:
        hostname = urlsplit(f"//{host}").hostname
    except ValueError:
        return False
    if not hostname:
        return False
    if hostname.lower() == "localhost" or hostname.lower().endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


class SQLitePolicyRepository:
    def __init__(self, database_path: Path | str) -> None:
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
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
                CREATE TABLE IF NOT EXISTS policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    secret_reference TEXT NOT NULL UNIQUE,
                    definition TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def store(self, document: PolicyDocument) -> PolicyRecord:
        now = datetime.now(UTC).isoformat()
        secret_reference = document.normalized_secret()
        definition = document.model_dump_json()
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT id, created_at FROM policies WHERE secret_reference = ?",
                (secret_reference,),
            ).fetchone()
            if existing is None:
                cursor = connection.execute(
                    """
                    INSERT INTO policies (secret_reference, definition, created_at, updated_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (secret_reference, definition, now, now),
                )
                policy_id = int(cursor.lastrowid)
                created_at = now
            else:
                policy_id = int(existing["id"])
                created_at = existing["created_at"]
                connection.execute(
                    """
                    UPDATE policies
                    SET definition = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (definition, now, policy_id),
                )
            connection.commit()
        return PolicyRecord(
            id=policy_id,
            secret_reference=secret_reference,
            definition=definition,
            created_at=datetime.fromisoformat(created_at),
            updated_at=datetime.fromisoformat(now),
        )

    def list(self) -> list[PolicyRecord]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM policies ORDER BY id ASC").fetchall()
        return [
            PolicyRecord(
                id=row["id"],
                secret_reference=row["secret_reference"],
                definition=row["definition"],
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
            )
            for row in rows
        ]

    def get(self, policy_id: int) -> PolicyRecord | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
        if row is None:
            return None
        return PolicyRecord(
            id=row["id"],
            secret_reference=row["secret_reference"],
            definition=row["definition"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def get_by_secret(self, secret_reference: str) -> PolicyRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM policies WHERE secret_reference = ?",
                (secret_reference,),
            ).fetchone()
        if row is None:
            return None
        return PolicyRecord(
            id=row["id"],
            secret_reference=row["secret_reference"],
            definition=row["definition"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def delete(self, policy_id: int) -> bool:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
            connection.commit()
            return cursor.rowcount > 0


class PolicyEngine:
    def __init__(self, repository: SQLitePolicyRepository) -> None:
        self._repository = repository

    def evaluate(self, secret_reference: SecretReference, destination: DestinationContext) -> PolicyDecision:
        record = self._repository.get_by_secret(secret_reference.canonical)
        if record is None:
            return PolicyDecision(
                allowed=False,
                reason="No policy registered for secret reference",
                secret_reference=secret_reference.canonical,
                destination=destination.host,
                method=destination.method,
            )

        document = PolicyDocument.from_yaml(record.definition)
        requested_method = destination.method.upper()
        requested_scheme = destination.scheme.lower()
        allowed_schemes = document.normalized_schemes()
        if allowed_schemes and requested_scheme not in allowed_schemes:
            return PolicyDecision(
                allowed=False,
                reason=f"scheme {requested_scheme} is not allowed",
                secret_reference=secret_reference.canonical,
                destination=destination.host,
                method=requested_method,
            )
        if not allowed_schemes and requested_scheme != "https" and not _is_loopback_destination(destination.host):
            return PolicyDecision(
                allowed=False,
                reason="insecure HTTP requires an explicit policy scheme",
                secret_reference=secret_reference.canonical,
                destination=destination.host,
                method=requested_method,
            )
        allowed_methods = document.normalized_methods()
        if allowed_methods and requested_method not in allowed_methods:
            return PolicyDecision(
                allowed=False,
                reason=f"method {requested_method} is not allowed",
                secret_reference=secret_reference.canonical,
                destination=destination.host,
                method=requested_method,
            )

        deny_hosts = [pattern.lower() for pattern in document.deny.hosts] if document.deny else []
        for pattern in deny_hosts:
            if fnmatch.fnmatch(destination.host, pattern):
                return PolicyDecision(
                    allowed=False,
                    reason=f"destination {destination.host} denied by pattern {pattern}",
                    secret_reference=secret_reference.canonical,
                    destination=destination.host,
                    method=requested_method,
                )

        allow_hosts = [pattern.lower() for pattern in document.allow.hosts] if document.allow else []
        if not allow_hosts:
            return PolicyDecision(
                allowed=False,
                reason="policy does not define any allowed hosts",
                secret_reference=secret_reference.canonical,
                destination=destination.host,
                method=requested_method,
            )

        if not any(fnmatch.fnmatch(destination.host, pattern) for pattern in allow_hosts):
            return PolicyDecision(
                allowed=False,
                reason=f"destination {destination.host} is not in allow list",
                secret_reference=secret_reference.canonical,
                destination=destination.host,
                method=requested_method,
            )

        return PolicyDecision(
            allowed=True,
            reason="allowed",
            secret_reference=secret_reference.canonical,
            destination=destination.host,
            method=requested_method,
        )
