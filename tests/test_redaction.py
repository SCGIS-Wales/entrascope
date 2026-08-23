"""Redaction tests. A secret that reaches a screen is a secret that has gone."""

from __future__ import annotations

from entrascope.config import Config


def test_credentials_in_an_address_are_redacted(config: Config) -> None:
    """A package index or a proxy address can carry a password, and pip echoes it."""
    from entrascope.redaction import redact_with_config

    line = "pip install --index-url https://build:hunter2@pypi.invalid/simple thing"
    redacted = str(redact_with_config(line, config))
    assert "hunter2" not in redacted
    assert "pypi.invalid" in redacted


def test_a_secret_in_a_query_string_is_redacted(config: Config) -> None:
    """A secret is a secret wherever the string came from."""
    from entrascope.redaction import redact_with_config

    line = "POST /token?client_secret=abc123&grant_type=client_credentials"
    redacted = str(redact_with_config(line, config))
    assert "abc123" not in redacted
    assert "grant_type=client_credentials" in redacted


def test_an_ordinary_address_is_left_alone(config: Config) -> None:
    """Redaction that eats the useful part of a log is redaction nobody keeps."""
    from entrascope.redaction import redact_with_config

    line = "https://graph.microsoft.com/v1.0/applications?$top=999"
    assert str(redact_with_config(line, config)) == line
