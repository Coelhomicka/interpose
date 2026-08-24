from __future__ import annotations

import pytest

from interpose.session.dotenv import DotenvValidationError, validate_dotenv
from interpose.session.profile import SessionProfile


def test_dotenv_accepts_expected_secret_references(tmp_path):
    profile = SessionProfile.from_yaml(
        """
version: 1
environment:
  API_KEY: secret://apichave/teste
"""
    )
    dotenv = tmp_path / ".env"
    dotenv.write_text("API_KEY=secret://apichave/teste\n", encoding="utf-8")

    validate_dotenv(dotenv, profile)


def test_dotenv_rejects_plaintext_without_echoing_it(tmp_path):
    profile = SessionProfile.from_yaml(
        """
version: 1
environment:
  API_KEY: secret://apichave/teste
"""
    )
    dotenv = tmp_path / ".env"
    dotenv.write_text("API_KEY=do-not-print-this-secret\n", encoding="utf-8")

    with pytest.raises(DotenvValidationError) as error:
        validate_dotenv(dotenv, profile)

    assert "potential plaintext credential" in str(error.value)
    assert "do-not-print-this-secret" not in str(error.value)


def test_dotenv_does_not_accept_shorthand_for_credential_values(tmp_path):
    profile = SessionProfile.from_yaml(
        """
version: 1
environment:
  API_KEY: secret://apichave/teste
"""
    )
    dotenv = tmp_path / ".env"
    dotenv.write_text("API_KEY=apichave/teste\n", encoding="utf-8")

    with pytest.raises(DotenvValidationError, match="does not contain a secret reference"):
        validate_dotenv(dotenv, profile)
