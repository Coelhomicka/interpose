from __future__ import annotations

import pytest

from interpose.core.references import SecretReference, SecretReferenceError


def test_secret_reference_parse():
    ref = SecretReference.parse("secret://github/prod")
    assert ref.provider == "github"
    assert ref.namespace == "github"
    assert ref.path == "prod"
    assert ref.canonical == "secret://github/prod"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "secret://",
        "http://github/prod",
        "secret://github",
        "secret://github/prod?x=1",
        "secret://github//prod",
        "secret://github/../prod",
    ],
)
def test_secret_reference_invalid(value):
    with pytest.raises(SecretReferenceError):
        SecretReference.parse(value)

