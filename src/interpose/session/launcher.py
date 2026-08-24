from __future__ import annotations

import os
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..core.audit import AuditLogger
from ..secrets.base import SecretStore
from .isolation.base import IsolationError
from .isolation.factory import create_isolation_backend
from .profile import SessionProfile

DEFAULT_PASSTHROUGH_ENVIRONMENT = frozenset(
    {
        "APPDATA",
        "COLORTERM",
        "COMSPEC",
        "DISPLAY",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LOCALAPPDATA",
        "LOGONSERVER",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROMPT",
        "PSMODULEPATH",
        "PUBLIC",
        "SHELL",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "VIRTUAL_ENV",
        "WAYLAND_DISPLAY",
        "WINDIR",
        "XDG_RUNTIME_DIR",
    }
)


class SessionLaunchError(RuntimeError):
    pass


def build_session_environment(
    profile: SessionProfile,
    *,
    agent: str,
    session: str,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    inherited = source if source is not None else os.environ
    allowed_names = DEFAULT_PASSTHROUGH_ENVIRONMENT | set(profile.runtime.pass_environment)
    environment = {
        name: value
        for name, value in inherited.items()
        if name.upper() in allowed_names or name in profile.runtime.pass_environment
    }

    environment.update(profile.public_environment)
    environment.update(profile.environment)
    environment["INTERPOSE_AGENT"] = agent
    environment["INTERPOSE_SESSION"] = session
    environment["INTERPOSE_MODE"] = "reference-only"
    environment.pop("INTERPOSE_MASTER_KEY", None)
    environment.pop("INTERPOSE_HOME", None)

    if profile.runtime.http_proxy:
        environment["HTTP_PROXY"] = profile.runtime.http_proxy
        environment["http_proxy"] = profile.runtime.http_proxy
        environment["NO_PROXY"] = ""
        environment["no_proxy"] = ""
        environment["INTERPOSE_HTTP_PROXY"] = profile.runtime.http_proxy
        environment.pop("HTTPS_PROXY", None)
        environment.pop("https_proxy", None)

    return environment


@dataclass
class SessionLauncher:
    secret_store: SecretStore
    audit_logger: AuditLogger
    runtime_home: Path

    def validate_bindings(self, profile: SessionProfile) -> None:
        missing = [reference for reference in profile.environment.values() if not self.secret_store.exists(reference)]
        if missing:
            raise SessionLaunchError(f"unknown secret references: {', '.join(sorted(missing))}")

    def run(
        self,
        command: Sequence[str],
        *,
        profile: SessionProfile,
        agent: str,
        session: str | None = None,
        cwd: Path | str | None = None,
    ) -> int:
        if not command:
            raise SessionLaunchError("session command cannot be empty")
        self.validate_bindings(profile)
        session_id = session or uuid.uuid4().hex
        environment = build_session_environment(profile, agent=agent, session=session_id)
        working_directory = Path(cwd or Path.cwd()).resolve()
        backend = create_isolation_backend(
            profile.runtime.isolation,
            session=session_id,
            runtime_home=self.runtime_home,
        )
        started = time.perf_counter()
        references = sorted(set(profile.environment.values()))
        try:
            return_code = backend.run(
                list(command),
                environment=environment,
                cwd=working_directory,
            )
            status = "success" if return_code == 0 else "error"
        except (OSError, IsolationError) as exc:
            return_code = 1
            status = "launch-error"
            raise SessionLaunchError(str(exc)) from exc
        finally:
            self.audit_logger.record(
                session=session_id,
                agent=agent,
                secret_reference=",".join(references) or "none",
                destination="local-process",
                action="SESSION_RUN",
                policy_result="not-applicable",
                status=status if "status" in locals() else "launch-error",
                duration_ms=int((time.perf_counter() - started) * 1000),
                details={
                    "executable": Path(command[0]).name,
                    "isolation": backend.name,
                    "return_code": return_code if "return_code" in locals() else 1,
                },
            )
        return return_code
