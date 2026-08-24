from __future__ import annotations

import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from ..core.references import normalize_secret_reference

ENVIRONMENT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SENSITIVE_ENVIRONMENT_NAME_RE = re.compile(
    r"(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY|ACCESS_?KEY|CLIENT_?SECRET)",
    re.IGNORECASE,
)


class SessionProfileError(ValueError):
    pass


class RuntimeSessionOptions(BaseModel):
    http_proxy: str | None = None
    pass_environment: list[str] = Field(default_factory=list)
    isolation: IsolationOptions = Field(default_factory=lambda: IsolationOptions())

    @field_validator("http_proxy")
    @classmethod
    def validate_http_proxy(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("http_proxy must be an HTTP URL on the loopback interface")
        if parsed.username or parsed.password or not parsed.port:
            raise ValueError("http_proxy must include a port and cannot include credentials")
        return value.rstrip("/")

    @field_validator("pass_environment")
    @classmethod
    def validate_pass_environment(cls, values: list[str]) -> list[str]:
        for value in values:
            if not ENVIRONMENT_NAME_RE.fullmatch(value):
                raise ValueError(f"invalid environment variable name: {value!r}")
        return values


class IsolationOptions(BaseModel):
    mode: Literal["none", "windows-appcontainer"] = "none"
    broker_url: str | None = None
    read_only_paths: list[str] = Field(default_factory=list)
    read_write_paths: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_isolation(self) -> IsolationOptions:
        if self.mode == "windows-appcontainer":
            if not self.broker_url:
                raise ValueError("windows-appcontainer isolation requires broker_url")
            parsed = urlsplit(self.broker_url)
            if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
                raise ValueError("windows-appcontainer broker_url must use http://127.0.0.1:<port>")
            if parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError("windows-appcontainer broker_url must contain only loopback host and port")
            self.broker_url = self.broker_url.rstrip("/")
        return self


RuntimeSessionOptions.model_rebuild()


class SessionProfile(BaseModel):
    version: int = 1
    environment: dict[str, str] = Field(default_factory=dict)
    public_environment: dict[str, str] = Field(default_factory=dict)
    runtime: RuntimeSessionOptions = Field(default_factory=RuntimeSessionOptions)

    @model_validator(mode="after")
    def validate_profile(self) -> SessionProfile:
        if self.version != 1:
            raise ValueError(f"unsupported profile version: {self.version}")
        normalized: dict[str, str] = {}
        for name, reference in self.environment.items():
            if not ENVIRONMENT_NAME_RE.fullmatch(name):
                raise ValueError(f"invalid environment variable name: {name!r}")
            normalized[name] = normalize_secret_reference(reference)
        for name, value in self.public_environment.items():
            if not ENVIRONMENT_NAME_RE.fullmatch(name):
                raise ValueError(f"invalid environment variable name: {name!r}")
            if name in normalized:
                raise ValueError(f"environment variable defined as both credential and public: {name}")
            if SENSITIVE_ENVIRONMENT_NAME_RE.search(name):
                raise ValueError(f"credential-like variable cannot be declared public: {name}")
            if "secret://" in value:
                raise ValueError(f"public environment variable cannot contain a secret reference: {name}")
        self.environment = normalized
        return self

    @classmethod
    def from_yaml(cls, source: str) -> SessionProfile:
        try:
            payload = yaml.safe_load(source)
        except yaml.YAMLError as exc:
            raise SessionProfileError(f"invalid profile YAML: {exc}") from exc
        if not isinstance(payload, dict):
            raise SessionProfileError("profile must be a YAML mapping")
        try:
            return cls.model_validate(payload)
        except ValueError as exc:
            raise SessionProfileError(str(exc)) from exc

    @classmethod
    def from_path(cls, path: Path | str) -> SessionProfile:
        profile_path = Path(path)
        if not profile_path.is_file():
            raise SessionProfileError(f"profile not found: {profile_path}")
        return cls.from_yaml(profile_path.read_text(encoding="utf-8"))
