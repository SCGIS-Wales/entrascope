"""Redaction tests. A secret that reaches a screen is a secret that has gone."""

from __future__ import annotations

from entrascope.config import Config


def test_credentials_in_an_address_are_redacted(config: Config) -> None:
    """A package index or a proxy address can carry a password, and pip echoes it."""
    from entrascope.redaction import redact_with_config

    line = "pip install --index-url https://build:hunter2@pypi.invalid/simple thing"
    redacted = str(redact_with_config(line, config))
    assert "hunter2" not in redacted
    # The whole line, so the test says what redaction produces rather than only
    # that one word survived it. The address is still readable, which is the
    # point: an index that cannot be reached is worth naming.
    assert redacted == (
        "pip install --index-url https://[redacted]@pypi.invalid/simple thing"
    )


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


def test_a_known_secret_is_redacted_in_a_rendered_report(config: Config) -> None:
    """A secret redacted in a log line and printed in a report is one that leaked.

    also_redact told the log handlers and nothing else, so a literal secret
    reaching the renderer came out whole. Both layers are told now.
    """
    from entrascope.logger import also_redact
    from entrascope.redaction import forget_secrets, redact_with_config

    try:
        also_redact("the-literal-secret")
        assert "the-literal-secret" not in str(
            redact_with_config("using the-literal-secret now", config)
        )
        assert "the-literal-secret" not in str(
            redact_with_config({"anything": "the-literal-secret"}, config)
        )
        assert "the-literal-secret" not in str(
            redact_with_config(["a", "the-literal-secret"], config)
        )
    finally:
        forget_secrets()


def test_a_secret_containing_another_is_replaced_whole(config: Config) -> None:
    """Shortest first would leave the tail of the longer one behind."""
    from entrascope.redaction import forget_secrets, redact_with_config, remember_secret

    try:
        remember_secret("abc")
        remember_secret("abcdef")
        assert "def" not in str(redact_with_config("abcdef", config))
    finally:
        forget_secrets()


def test_forgetting_a_secret_leaves_the_configured_patterns_alone(
    config: Config,
) -> None:
    """The patterns are configuration and are not affected by what was remembered."""
    from entrascope.redaction import forget_secrets, redact_with_config

    forget_secrets()
    assert "[redacted]" in str(redact_with_config({"client_secret": "x"}, config))
