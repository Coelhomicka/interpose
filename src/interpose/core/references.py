from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

SECRET_URI_PREFIX = "secret://"
SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SECRET_URI_RE = re.compile(
    r"secret://[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*"
)


class SecretReferenceError(ValueError):
    pass


def _normalize_segment(segment: str, *, field_name: str) -> str:
    value = segment.strip()
    if not value:
        raise SecretReferenceError(f"{field_name} cannot be empty")
    if value in {".", ".."}:
        raise SecretReferenceError(f"{field_name} cannot contain path traversal segments")
    if not SEGMENT_RE.fullmatch(value):
        raise SecretReferenceError(f"{field_name} contains invalid characters: {segment!r}")
    return value.lower() if field_name == "provider" else value


@dataclass(frozen=True, slots=True)
class SecretReference:
    provider: str
    segments: tuple[str, ...]
    raw: str = ""

    @classmethod
    def parse(cls, value: str) -> SecretReference:
        if not isinstance(value, str):
            raise SecretReferenceError("secret reference must be a string")
        raw = value.strip()
        if not raw:
            raise SecretReferenceError("secret reference cannot be empty")
        parsed = urlsplit(raw)
        if parsed.scheme != "secret":
            raise SecretReferenceError("secret reference must use secret:// scheme")
        if not parsed.netloc:
            raise SecretReferenceError("secret reference must include a provider")
        if parsed.query or parsed.fragment:
            raise SecretReferenceError("secret reference must not contain query or fragment components")
        raw_segments = parsed.path.split("/")
        if len(raw_segments) < 2:
            raise SecretReferenceError("secret reference must include at least one path segment")
        if raw_segments[0] != "" or any(segment == "" for segment in raw_segments[1:]):
            raise SecretReferenceError("secret reference must not contain empty path segments")
        provider = _normalize_segment(parsed.netloc, field_name="provider")
        normalized_segments = tuple(_normalize_segment(segment, field_name="segment") for segment in raw_segments[1:])
        return cls(provider=provider, segments=normalized_segments, raw=raw)

    @property
    def namespace(self) -> str:
        if len(self.segments) == 1:
            return self.provider
        return f"{self.provider}/{self.segments[0]}"

    @property
    def path(self) -> str:
        return "/".join(self.segments)

    @property
    def name(self) -> str:
        return self.segments[-1]

    @property
    def environment(self) -> str | None:
        if len(self.segments) < 2:
            return None
        return self.segments[0]

    @property
    def canonical(self) -> str:
        return f"{SECRET_URI_PREFIX}{self.provider}/{self.path}"

    def __str__(self) -> str:
        return self.canonical

    def matches(self, other: str | SecretReference) -> bool:
        candidate = other if isinstance(other, SecretReference) else SecretReference.parse(other)
        return self.canonical == candidate.canonical


def normalize_secret_reference(value: str) -> str:
    raw = value.strip()
    candidate = raw if raw.startswith(SECRET_URI_PREFIX) else f"{SECRET_URI_PREFIX}{raw}"
    return SecretReference.parse(candidate).canonical


def find_secret_references_in_text(text: str) -> tuple[SecretReference, ...]:
    matches = []
    seen: set[str] = set()
    for match in SECRET_URI_RE.finditer(text):
        ref = SecretReference.parse(match.group(0))
        if ref.canonical not in seen:
            seen.add(ref.canonical)
            matches.append(ref)
    return tuple(matches)


def collect_secret_references(value: Any) -> tuple[SecretReference, ...]:
    refs: list[SecretReference] = []
    seen: set[str] = set()

    def visit(item: Any) -> None:
        if isinstance(item, str):
            for ref in find_secret_references_in_text(item):
                if ref.canonical not in seen:
                    seen.add(ref.canonical)
                    refs.append(ref)
            return
        if isinstance(item, dict):
            for key, sub_value in item.items():
                visit(key)
                visit(sub_value)
            return
        if isinstance(item, (list, tuple, set)):
            for sub_item in item:
                visit(sub_item)
            return

    visit(value)
    return tuple(refs)
