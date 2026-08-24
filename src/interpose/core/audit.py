from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..models import AuditEntryResponse


class AuditLogger:
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
                CREATE TABLE IF NOT EXISTS audit_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    session TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    secret_reference TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    action TEXT NOT NULL,
                    policy_result TEXT NOT NULL,
                    status TEXT NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )

    def record(
        self,
        *,
        session: str,
        agent: str,
        secret_reference: str,
        destination: str,
        action: str,
        policy_result: str,
        status: str,
        duration_ms: int,
        details: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> int:
        ts = (timestamp or datetime.now(UTC)).isoformat()
        payload = json.dumps(details or {}, sort_keys=True)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO audit_entries (
                    timestamp, session, agent, secret_reference, destination,
                    action, policy_result, status, duration_ms, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    session,
                    agent,
                    secret_reference,
                    destination,
                    action,
                    policy_result,
                    status,
                    duration_ms,
                    payload,
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def list(self, limit: int = 100) -> list[AuditEntryResponse]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_entries ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        result: list[AuditEntryResponse] = []
        for row in rows:
            result.append(
                AuditEntryResponse(
                    id=row["id"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    session=row["session"],
                    agent=row["agent"],
                    secret_reference=row["secret_reference"],
                    destination=row["destination"],
                    action=row["action"],
                    policy_result=row["policy_result"],
                    status=row["status"],
                    duration_ms=row["duration_ms"],
                    details=json.loads(row["details"]),
                )
            )
        return result

