from __future__ import annotations

from pathlib import Path

from ..profile import IsolationOptions
from .base import IsolationBackend, IsolationError, NoIsolationBackend


def create_isolation_backend(
    options: IsolationOptions,
    *,
    session: str,
    runtime_home: Path,
) -> IsolationBackend:
    if options.mode == "none":
        return NoIsolationBackend()
    if options.mode == "windows-appcontainer":
        from .windows_appcontainer import WindowsAppContainerBackend

        return WindowsAppContainerBackend(options=options, session=session, runtime_home=runtime_home)
    raise IsolationError(f"unsupported isolation mode: {options.mode}")
