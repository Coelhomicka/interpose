from __future__ import annotations

import re
from pathlib import Path

from ..core.references import SecretReferenceError, normalize_secret_reference
from .profile import SessionProfile

SENSITIVE_ENVIRONMENT_NAME_RE = re.compile(
    r"(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY|ACCESS_?KEY|CLIENT_?SECRET)",
    re.IGNORECASE,
)


class DotenvValidationError(ValueError):
    pass


def parse_dotenv(source: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise DotenvValidationError(f"invalid .env assignment on line {line_number}")
        name, raw_value = line.split("=", 1)
        name = name.strip()
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[name] = value
    return values


def validate_dotenv(path: Path | str, profile: SessionProfile) -> None:
    dotenv_path = Path(path)
    if not dotenv_path.is_file():
        raise DotenvValidationError(f".env file not found: {dotenv_path}")
    values = parse_dotenv(dotenv_path.read_text(encoding="utf-8"))
    errors: list[str] = []

    for name, expected_value in profile.public_environment.items():
        candidate = values.get(name)
        if candidate is None:
            errors.append(f"missing required public variable: {name}")
        elif candidate != expected_value:
            errors.append(f"public variable uses an unexpected value: {name}")

    for name, expected_reference in profile.environment.items():
        candidate = values.get(name)
        if candidate is None:
            errors.append(f"missing required reference variable: {name}")
            continue
        if not candidate.startswith("secret://"):
            errors.append(f"credential variable does not contain a secret reference: {name}")
            continue
        try:
            actual_reference = normalize_secret_reference(candidate)
        except SecretReferenceError:
            errors.append(f"credential variable does not contain a secret reference: {name}")
            continue
        if actual_reference != expected_reference:
            errors.append(f"credential variable uses an unexpected secret reference: {name}")

    for name, value in values.items():
        if not SENSITIVE_ENVIRONMENT_NAME_RE.search(name):
            continue
        if not value.startswith("secret://"):
            errors.append(f"potential plaintext credential in variable: {name}")
            continue
        try:
            normalize_secret_reference(value)
        except SecretReferenceError:
            errors.append(f"potential plaintext credential in variable: {name}")

    if errors:
        raise DotenvValidationError("; ".join(dict.fromkeys(errors)))
