from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core.audit import AuditLogger
from ..core.policies import PolicyEngine
from ..core.redaction import SecretRedactionEngine
from ..core.references import collect_secret_references
from ..core.substitution import SecretSubstitutionEngine
from ..models import DestinationContext, ExecutionResult, ResolvedSecret
from ..secrets.base import SecretStore


class PolicyViolationError(RuntimeError):
    pass


class ExecutionPreparationError(RuntimeError):
    pass


URL_RE = re.compile(r"https?://[^\s'\"`]+")


def _infer_method(command: Sequence[str]) -> str:
    if not command:
        return "EXEC"
    command_name = re.split(r"[\\/]", command[0])[-1].lower()
    if command_name not in {"curl", "curl.exe"}:
        return "EXEC"
    method = "GET"
    for index, token in enumerate(command):
        if token == "-X" and index + 1 < len(command):
            method = command[index + 1].upper()
    return method


def _infer_destinations(command: Sequence[str]) -> list[DestinationContext]:
    method = _infer_method(command)
    destinations: list[DestinationContext] = []
    seen: set[str] = set()
    for token in command:
        for match in URL_RE.finditer(token):
            parsed = urlparse(match.group(0))
            if not parsed.hostname:
                continue
            host = parsed.hostname
            if parsed.port:
                host = f"{host}:{parsed.port}"
            key = f"{host}:{method}"
            if key not in seen:
                seen.add(key)
                destinations.append(
                    DestinationContext(
                        host=host,
                        method=method,
                        scheme=parsed.scheme,
                        url=parsed.geturl(),
                    )
                )
    return destinations


@dataclass
class TrustedExecutor:
    secret_store: SecretStore
    policy_engine: PolicyEngine
    audit_logger: AuditLogger
    redaction_engine: SecretRedactionEngine
    agent_name: str = "unknown"

    def _resolve_secret(self, reference) -> ResolvedSecret:
        return self.secret_store.resolve(reference)

    def execute(
        self,
        command: Sequence[str],
        *,
        session: str = "local",
        agent: str | None = None,
        destination: DestinationContext | None = None,
    ) -> ExecutionResult:
        if not command:
            raise ExecutionPreparationError("command cannot be empty")

        start = time.perf_counter()
        resolved_agent = (agent or self.agent_name or "unknown").strip() or "unknown"
        references = collect_secret_references(command)
        inferred_destinations = [destination] if destination else _infer_destinations(command)

        if references and not inferred_destinations:
            duration_ms = int((time.perf_counter() - start) * 1000)
            self.audit_logger.record(
                session=session,
                agent=resolved_agent,
                secret_reference=",".join(reference.canonical for reference in references),
                destination="unknown",
                action="EXEC",
                policy_result="deny",
                status="blocked",
                duration_ms=duration_ms,
                details={"reason": "destination could not be inferred"},
            )
            raise PolicyViolationError("destination could not be inferred for secret usage")

        if len({context.host for context in inferred_destinations}) > 1:
            duration_ms = int((time.perf_counter() - start) * 1000)
            self.audit_logger.record(
                session=session,
                agent=resolved_agent,
                secret_reference=",".join(reference.canonical for reference in references),
                destination=",".join(context.host for context in inferred_destinations),
                action="EXEC",
                policy_result="deny",
                status="blocked",
                duration_ms=duration_ms,
                details={"reason": "multiple destinations detected"},
            )
            raise PolicyViolationError("multiple destinations detected; explicit destination handling is required")

        active_destination = (
            inferred_destinations[0]
            if inferred_destinations
            else DestinationContext(host="unknown", method="EXEC")
        )

        for reference in references:
            decision = self.policy_engine.evaluate(reference, active_destination)
            if not decision.allowed:
                duration_ms = int((time.perf_counter() - start) * 1000)
                self.audit_logger.record(
                    session=session,
                    agent=resolved_agent,
                    secret_reference=reference.canonical,
                    destination=active_destination.host,
                    action=f"HTTP_{active_destination.method}" if active_destination.method != "EXEC" else "EXEC",
                    policy_result="deny",
                    status="blocked",
                    duration_ms=duration_ms,
                    details={"reason": decision.reason},
                )
                raise PolicyViolationError(decision.reason)

        substitution = SecretSubstitutionEngine(self._resolve_secret)
        substitution_result = substitution.substitute(list(command))
        resolved_command = list(substitution_result.value)
        resolved_values = [resolution.value for resolution in substitution_result.resolutions]
        self.redaction_engine.register_many(resolved_values)

        try:
            completed = subprocess.run(
                resolved_command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            stdout = self.redaction_engine.redact(completed.stdout)
            stderr = self.redaction_engine.redact(completed.stderr)
            status = "success" if completed.returncode == 0 else "error"
            policy_result = "allow"
            return_code = int(completed.returncode)
        except Exception as exc:
            stdout = ""
            stderr = self.redaction_engine.redact(str(exc))
            status = "error"
            policy_result = "allow"
            return_code = 1
        duration_ms = int((time.perf_counter() - start) * 1000)
        self.audit_logger.record(
            session=session,
            agent=resolved_agent,
            secret_reference=",".join(reference.canonical for reference in references) or "none",
            destination=active_destination.host,
            action=f"HTTP_{active_destination.method}" if active_destination.method != "EXEC" else "EXEC",
            policy_result=policy_result,
            status=status,
            duration_ms=duration_ms,
            details={"return_code": return_code},
        )
        return ExecutionResult(
            command=tuple(resolved_command),
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            allowed=True,
            policy_result=policy_result,
            destination=active_destination.host,
            duration_ms=duration_ms,
        )
