from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol


class IsolationError(RuntimeError):
    pass


class IsolationBackend(Protocol):
    name: str

    def run(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        cwd: Path,
    ) -> int:
        raise NotImplementedError


class NoIsolationBackend:
    name = "none"

    def run(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        cwd: Path,
    ) -> int:
        completed = subprocess.run(list(command), cwd=str(cwd), env=dict(environment), check=False)
        return int(completed.returncode)
