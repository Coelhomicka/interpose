from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..models import ResolvedSecret, SubstitutionResult
from .references import SECRET_URI_RE, SecretReference, collect_secret_references

Resolver = Callable[[SecretReference], ResolvedSecret]


@dataclass
class SecretSubstitutionEngine:
    resolver: Resolver

    def substitute_text(self, text: str) -> SubstitutionResult:
        references = collect_secret_references(text)
        resolved_map: dict[str, ResolvedSecret] = {}
        for reference in references:
            resolved_map[reference.canonical] = self.resolver(reference)

        def replace(match: Any) -> str:
            canonical = SecretReference.parse(match.group(0)).canonical
            return resolved_map[canonical].value

        substituted = SECRET_URI_RE.sub(replace, text)
        return SubstitutionResult(
            value=substituted,
            references=tuple(reference.canonical for reference in references),
            resolutions=tuple(resolved_map[reference.canonical] for reference in references),
        )

    def substitute(self, value: Any) -> SubstitutionResult:
        references = collect_secret_references(value)
        resolved_map: dict[str, ResolvedSecret] = {}
        for reference in references:
            resolved_map[reference.canonical] = self.resolver(reference)

        def walk(item: Any) -> Any:
            if isinstance(item, str):
                def replace(match: Any) -> str:
                    canonical = SecretReference.parse(match.group(0)).canonical
                    return resolved_map[canonical].value

                return SECRET_URI_RE.sub(replace, item)
            if isinstance(item, dict):
                return {walk(key): walk(sub_value) for key, sub_value in item.items()}
            if isinstance(item, list):
                return [walk(sub_item) for sub_item in item]
            if isinstance(item, tuple):
                return tuple(walk(sub_item) for sub_item in item)
            if isinstance(item, set):
                return {walk(sub_item) for sub_item in item}
            return item

        return SubstitutionResult(
            value=walk(value),
            references=tuple(reference.canonical for reference in references),
            resolutions=tuple(resolved_map[reference.canonical] for reference in references),
        )

