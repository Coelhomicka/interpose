from __future__ import annotations

import base64
import ctypes
import hashlib
import os
import re
import shutil
import socket
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from ..profile import IsolationOptions
from .base import IsolationError
from .windows_native import WindowsNativeAppContainer

SID_RE = re.compile(r"^S-1-15-2(?:-\d+)+$")


def _run_checked(command: Sequence[str], operation: str) -> None:
    completed = subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise IsolationError(f"{operation} failed ({completed.returncode}): {detail}")


def _run_powershell(script: str, operation: str) -> None:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    _run_checked(
        [
            os.path.join(
                os.environ.get("SYSTEMROOT", r"C:\Windows"),
                "System32",
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe",
            ),
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded,
        ],
        operation,
    )


def _is_administrator() -> bool:
    if os.name != "nt":
        return False
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


@dataclass
class WindowsAppContainerBackend:
    options: IsolationOptions
    session: str
    runtime_home: Path
    name: str = "windows-appcontainer"

    def doctor(self) -> list[tuple[str, bool, str]]:
        checks: list[tuple[str, bool, str]] = []
        checks.append(("platform", os.name == "nt", "Windows is required"))
        checks.append(("administrator", _is_administrator(), "elevated terminal is required"))
        checks.append(("icacls", shutil.which("icacls.exe") is not None, "icacls.exe is required"))
        checks.append(
            (
                "CheckNetIsolation",
                shutil.which("CheckNetIsolation.exe") is not None,
                "CheckNetIsolation.exe is required",
            )
        )
        checks.append(("firewall", shutil.which("powershell.exe") is not None, "Windows PowerShell is required"))
        try:
            diagnostic_name = self._profile_name(suffix="doctor")
            self._profile_helper("create", diagnostic_name)
            self._profile_helper("delete", diagnostic_name)
            checks.append(("appcontainer_api", True, "profile create/delete succeeded"))
        except IsolationError as exc:
            checks.append(("appcontainer_api", False, str(exc)))
        try:
            self._check_broker()
            checks.append(("broker", True, "broker is reachable"))
        except IsolationError as exc:
            checks.append(("broker", False, str(exc)))
        return checks

    def run(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        cwd: Path,
    ) -> int:
        if os.name != "nt":
            raise IsolationError("windows-appcontainer isolation is only available on Windows")
        if not _is_administrator():
            raise IsolationError("windows-appcontainer isolation requires an elevated terminal")
        self._check_broker()
        native = WindowsNativeAppContainer()
        profile_name = self._profile_name()
        self._profile_helper("create", profile_name)
        sid_pointer = native.derive_profile_sid(profile_name)
        sid = native.sid_to_string(sid_pointer)
        if not SID_RE.fullmatch(sid):
            native.free_sid(sid_pointer)
            self._profile_helper("delete", profile_name)
            raise IsolationError("Windows returned an invalid AppContainer SID")

        acl_paths: list[Path] = []
        firewall_rules: list[str] = []
        loopback_added = False
        primary_error: BaseException | None = None
        try:
            acl_paths = self._grant_filesystem_access(sid, cwd)
            self._set_loopback_exemption(sid, add=True)
            loopback_added = True
            firewall_rules = self._add_loopback_firewall_rules(sid)
            return native.launch(
                command,
                environment=environment,
                cwd=cwd,
                appcontainer_sid=sid_pointer,
            )
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            cleanup_errors: list[str] = []
            if firewall_rules:
                try:
                    self._remove_firewall_rules(firewall_rules)
                except IsolationError as exc:
                    cleanup_errors.append(str(exc))
            if loopback_added:
                try:
                    self._set_loopback_exemption(sid, add=False)
                except IsolationError as exc:
                    cleanup_errors.append(str(exc))
            for path in reversed(acl_paths):
                try:
                    self._remove_path_access(path, sid)
                except IsolationError as exc:
                    cleanup_errors.append(str(exc))
            native.free_sid(sid_pointer)
            try:
                self._profile_helper("delete", profile_name)
            except IsolationError as exc:
                cleanup_errors.append(str(exc))
            if cleanup_errors and primary_error is None:
                raise IsolationError("isolation cleanup failed: " + "; ".join(cleanup_errors))
            if cleanup_errors and primary_error is not None:
                primary_error.add_note("isolation cleanup errors: " + "; ".join(cleanup_errors))

    def _profile_name(self, *, suffix: str = "session") -> str:
        digest = hashlib.sha256(f"{self.session}:{suffix}".encode()).hexdigest()[:20]
        return f"SecretRuntime.Agent.{digest}"

    def _profile_helper(self, operation: str, profile_name: str) -> None:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "secret_runtime.session.isolation.windows_profile_helper",
                operation,
                profile_name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            stdout, stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise IsolationError(f"AppContainer profile {operation} timed out") from exc
        except BaseException:
            process.kill()
            process.wait()
            raise
        if process.returncode != 0:
            detail = (stderr or stdout).strip()
            raise IsolationError(f"AppContainer profile {operation} failed ({process.returncode}): {detail}")

    def _check_broker(self) -> None:
        if not self.options.broker_url:
            raise IsolationError("broker_url is required")
        parsed = urlsplit(self.options.broker_url)
        try:
            with socket.create_connection((parsed.hostname or "", parsed.port or 0), timeout=2):
                return
        except OSError as exc:
            raise IsolationError(f"broker is not reachable at {self.options.broker_url}") from exc

    def _validated_path(self, raw_path: str | Path) -> Path:
        path = Path(raw_path).expanduser().resolve(strict=True)
        if path.parent == path:
            raise IsolationError(f"refusing to grant AppContainer access to drive root: {path}")
        runtime_home = self.runtime_home.resolve(strict=False)
        if path == runtime_home or runtime_home.is_relative_to(path) or path.is_relative_to(runtime_home):
            raise IsolationError(f"refusing to expose Secret Runtime storage through isolation ACL: {path}")
        return path

    def _grant_filesystem_access(self, sid: str, cwd: Path) -> list[Path]:
        requested_grants: list[tuple[Path, str]] = [(self._validated_path(cwd), "M")]
        requested_grants.extend((self._validated_path(path), "RX") for path in self.options.read_only_paths)
        requested_grants.extend((self._validated_path(path), "M") for path in self.options.read_write_paths)
        grants_by_path: dict[Path, str] = {}
        for path, permission in requested_grants:
            if permission == "M" or path not in grants_by_path:
                grants_by_path[path] = permission
        completed: list[Path] = []
        try:
            for path, permission in grants_by_path.items():
                inheritance = f"(OI)(CI){permission}" if path.is_dir() else permission
                _run_checked(
                    ["icacls.exe", str(path), "/grant", f"*{sid}:{inheritance}", "/T", "/C", "/Q", "/L"],
                    f"grant AppContainer access to {path}",
                )
                completed.append(path)
        except IsolationError:
            for path in reversed(completed):
                self._remove_path_access(path, sid)
            raise
        return completed

    def _remove_path_access(self, path: Path, sid: str) -> None:
        _run_checked(
            ["icacls.exe", str(path), "/remove:g", f"*{sid}", "/T", "/C", "/Q", "/L"],
            f"remove AppContainer access from {path}",
        )

    def _set_loopback_exemption(self, sid: str, *, add: bool) -> None:
        operation = "-a" if add else "-d"
        _run_checked(
            ["CheckNetIsolation.exe", "LoopbackExempt", operation, f"-p={sid}"],
            f"{'add' if add else 'remove'} AppContainer loopback exemption",
        )

    def _add_loopback_firewall_rules(self, sid: str) -> list[str]:
        port = urlsplit(self.options.broker_url or "").port
        if port is None:
            raise IsolationError("broker_url port is required")
        prefix = f"SecretRuntime-{hashlib.sha256(self.session.encode()).hexdigest()[:16]}"
        rules: list[tuple[str, str, str]] = []
        if port > 1:
            rules.extend(
                [
                    (f"{prefix}-tcp4-low", "127.0.0.0/8", f"1-{port - 1}"),
                    (f"{prefix}-tcp6-low", "::1", f"1-{port - 1}"),
                ]
            )
        if port < 65535:
            rules.extend(
                [
                    (f"{prefix}-tcp4-high", "127.0.0.0/8", f"{port + 1}-65535"),
                    (f"{prefix}-tcp6-high", "::1", f"{port + 1}-65535"),
                ]
            )
        rule_names = [name for name, _, _ in rules] + [
            f"{prefix}-tcp4-other-loopback",
            f"{prefix}-udp4",
            f"{prefix}-udp6",
        ]
        commands = ["$ErrorActionPreference = 'Stop'"]
        for name, address, ports in rules:
            commands.append(
                "New-NetFirewallRule "
                f"-Name '{name}' -DisplayName '{name}' -Direction Outbound -Action Block "
                f"-Enabled True -Profile Any -Package '{sid}' -Protocol TCP "
                f"-RemoteAddress '{address}' -RemotePort '{ports}' | Out-Null"
            )
        commands.extend(
            [
                "New-NetFirewallRule "
                f"-Name '{prefix}-tcp4-other-loopback' -DisplayName '{prefix}-tcp4-other-loopback' "
                "-Direction Outbound -Action Block -Enabled True -Profile Any "
                f"-Package '{sid}' -Protocol TCP -RemoteAddress '127.0.0.2-127.255.255.255' | Out-Null",
                "New-NetFirewallRule "
                f"-Name '{prefix}-udp4' -DisplayName '{prefix}-udp4' -Direction Outbound -Action Block "
                f"-Enabled True -Profile Any -Package '{sid}' -Protocol UDP -RemoteAddress '127.0.0.0/8' | Out-Null",
                "New-NetFirewallRule "
                f"-Name '{prefix}-udp6' -DisplayName '{prefix}-udp6' -Direction Outbound -Action Block "
                f"-Enabled True -Profile Any -Package '{sid}' -Protocol UDP -RemoteAddress '::1' | Out-Null",
            ]
        )
        try:
            _run_powershell("\n".join(commands), "create AppContainer firewall rules")
        except IsolationError:
            self._remove_firewall_rules(rule_names)
            raise
        return rule_names

    def _remove_firewall_rules(self, names: Sequence[str]) -> None:
        quoted_names = ",".join(f"'{name}'" for name in names)
        script = (
            "$ErrorActionPreference = 'Stop'\n"
            f"$names = @({quoted_names})\n"
            "foreach ($name in $names) { Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue }"
        )
        _run_powershell(script, "remove AppContainer firewall rules")
