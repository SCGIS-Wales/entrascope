"""Common logger and redaction tests."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from entrascope.config import Config, load_config
from entrascope.logger import (
    ROOT_NAME,
    bind_context,
    clear_context,
    configure_logging,
    get_correlation_id,
    get_logger,
    new_correlation_id,
    set_correlation_id,
    surface_settings,
)
from entrascope.redaction import (
    redact,
    redact_text,
    redact_with_config,
    register_secret,
)
from tests.conftest import SENTINEL_SECRET


@pytest.fixture
def config() -> Config:
    """Return the repository configuration."""
    return load_config()


@pytest.fixture(autouse=True)
def clean_context() -> Any:
    """Reset the correlation id and context between tests."""
    clear_context()
    yield
    clear_context()
    logging.getLogger(ROOT_NAME).handlers.clear()


def read_json_lines(path: Path) -> list[dict[str, Any]]:
    """Parse a log file written in JSON lines format."""
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_redaction_replaces_configured_keys(config: Config) -> None:
    """A value under a secret key is replaced wherever it appears."""
    payload = {"Secret": SENTINEL_SECRET, "ok": "visible"}
    result = redact_with_config(payload, config)
    assert result["Secret"] == config.logging.redaction.placeholder
    assert result["ok"] == "visible"


def test_redaction_is_case_insensitive_on_keys(config: Config) -> None:
    """Key matching ignores case, so clientSecret and CLIENTSECRET both go."""
    payload = {"clientSecret": SENTINEL_SECRET, "AUTHORIZATION": "Bearer abc.def.ghi"}
    result = redact_with_config(payload, config)
    assert SENTINEL_SECRET not in json.dumps(result)
    assert "abc.def.ghi" not in json.dumps(result)


def test_redaction_walks_nested_structures(config: Config) -> None:
    """Mappings inside sequences inside mappings are all walked."""
    payload = {"outer": [{"inner": {"password": SENTINEL_SECRET}}, "plain"]}
    assert SENTINEL_SECRET not in json.dumps(redact_with_config(payload, config))


def test_redaction_catches_a_bearer_token_anywhere(config: Config) -> None:
    """A bearer token in free text is replaced by pattern, not by key."""
    text = "request failed with Authorization: Bearer abc123.def456.ghi789 attached"
    assert "abc123" not in redact_text(text, config.logging.redaction)


def test_redaction_catches_a_json_web_token(config: Config) -> None:
    """A token shaped value is replaced even without a bearer prefix."""
    token = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJhcGkifQ.c2lnbmF0dXJl"
    assert token not in redact_text(token, config.logging.redaction)


def test_register_secret_adds_a_literal_pattern(config: Config) -> None:
    """Once the secret is known it is replaced even in an unrecognised position."""
    settings = register_secret(SENTINEL_SECRET, config.logging.redaction)
    assert SENTINEL_SECRET not in redact_text(f"value={SENTINEL_SECRET}", settings)


def test_register_secret_is_idempotent(config: Config) -> None:
    """Registering the same secret twice does not grow the pattern list."""
    once = register_secret(SENTINEL_SECRET, config.logging.redaction)
    twice = register_secret(SENTINEL_SECRET, once)
    assert len(once.patterns) == len(twice.patterns)


def test_register_secret_ignores_an_empty_secret(config: Config) -> None:
    """An empty secret adds no pattern, which would otherwise match everything."""
    assert register_secret("", config.logging.redaction) is config.logging.redaction


def test_redaction_leaves_non_strings_alone(config: Config) -> None:
    """Numbers and booleans pass through untouched."""
    payload = {"count": 3, "enabled": True, "items": (1, 2)}
    assert redact_with_config(payload, config) == payload


def test_redaction_is_depth_bounded(config: Config) -> None:
    """A deeply nested structure terminates rather than recursing without limit."""
    payload: dict[str, Any] = {"level": SENTINEL_SECRET}
    for _ in range(50):
        payload = {"level": payload}
    assert redact(payload, config.logging.redaction) is not None


def test_logger_redacts_secret_in_structure(tmp_path: Path, config: Config) -> None:
    """A secret logged inside a structure never reaches the handler."""
    destination = tmp_path / "log.jsonl"
    settings = config.model_copy(
        update={
            "logging": config.logging.model_copy(
                update={"destination": str(destination), "format": "json"}
            )
        }
    )
    configure_logging(settings, surface="unknown-surface")
    get_logger("demo").warning("payload %s", {"Secret": SENTINEL_SECRET})
    body = destination.read_text()
    assert SENTINEL_SECRET not in body
    assert config.logging.redaction.placeholder in body


def test_logger_correlation_id_is_attached_and_stable(
    tmp_path: Path, config: Config
) -> None:
    """Every record carries the same correlation id within one invocation."""
    destination = tmp_path / "log.jsonl"
    settings = config.model_copy(
        update={
            "logging": config.logging.model_copy(
                update={"destination": str(destination), "format": "json"}
            )
        }
    )
    configure_logging(settings, surface="unknown-surface")
    correlation = new_correlation_id()
    log = get_logger("demo")
    log.warning("first")
    log.warning("second")
    records = read_json_lines(destination)
    assert [record["correlation_id"] for record in records] == [correlation] * 2


def test_correlation_id_can_be_supplied_from_outside() -> None:
    """A correlation id from an HTTP header replaces the generated one."""
    set_correlation_id("from-a-header")
    assert get_correlation_id() == "from-a-header"


def test_correlation_id_is_generated_on_demand() -> None:
    """Reading the correlation id when none is set generates one."""
    clear_context()
    assert get_correlation_id()


def test_logger_json_format_carries_context(tmp_path: Path, config: Config) -> None:
    """Bound context fields appear on every record."""
    destination = tmp_path / "log.jsonl"
    settings = config.model_copy(
        update={
            "logging": config.logging.model_copy(
                update={"destination": str(destination), "format": "json"}
            )
        }
    )
    configure_logging(settings, surface="unknown-surface")
    bind_context(auth_source="azure-cli", tenant_id="contoso")
    get_logger("demo").error("failed")
    record = read_json_lines(destination)[0]
    assert record["auth_source"] == "azure-cli"
    assert record["tenant_id"] == "contoso"
    assert record["level"] == "ERROR"
    assert record["logger"] == "entrascope.demo"


def test_unlisted_context_fields_are_not_attached(
    tmp_path: Path, config: Config
) -> None:
    """Only the context fields named in configuration are attached."""
    destination = tmp_path / "log.jsonl"
    settings = config.model_copy(
        update={
            "logging": config.logging.model_copy(
                update={"destination": str(destination), "format": "json"}
            )
        }
    )
    configure_logging(settings, surface="unknown-surface")
    bind_context(not_configured="value")
    get_logger("demo").info("hello")
    assert "not_configured" not in read_json_lines(destination)[0]


def test_human_format_is_readable(tmp_path: Path, config: Config) -> None:
    """The human format carries the level, a short correlation id and the message."""
    destination = tmp_path / "log.txt"
    settings = config.model_copy(
        update={
            "logging": config.logging.model_copy(
                update={"destination": str(destination), "format": "human"}
            )
        }
    )
    configure_logging(settings, surface="unknown-surface")
    get_logger("demo").error("credential file mode is 0644")
    line = destination.read_text().strip()
    assert line.startswith("ERROR")
    assert "credential file mode is 0644" in line


def test_surface_overrides_apply(config: Config) -> None:
    """Each surface may override the format and the destination."""
    assert surface_settings(config.logging, "mcp_http") == ("json", "stdout")
    assert surface_settings(config.logging, "mcp_stdio") == ("json", "stderr")
    assert surface_settings(config.logging, "cli")[0] == "human"


def test_configuring_twice_does_not_duplicate_output(
    tmp_path: Path, config: Config
) -> None:
    """Repeated configuration replaces handlers rather than adding to them."""
    destination = tmp_path / "log.jsonl"
    settings = config.model_copy(
        update={
            "logging": config.logging.model_copy(
                update={"destination": str(destination), "format": "json"}
            )
        }
    )
    configure_logging(settings, surface="unknown-surface")
    configure_logging(settings, surface="unknown-surface")
    get_logger("demo").info("once")
    assert len(read_json_lines(destination)) == 1


def test_get_logger_namespaces_every_module() -> None:
    """A logger is always a child of the entrascope logger."""
    assert get_logger("graph").name == "entrascope.graph"
    assert get_logger("entrascope.graph").name == "entrascope.graph"
    assert get_logger(ROOT_NAME).name == ROOT_NAME


def test_exception_is_recorded(tmp_path: Path, config: Config) -> None:
    """An exception logged with exc_info reaches the record as text."""
    destination = tmp_path / "log.jsonl"
    settings = config.model_copy(
        update={
            "logging": config.logging.model_copy(
                update={"destination": str(destination), "format": "json"}
            )
        }
    )
    configure_logging(settings, surface="unknown-surface")
    try:
        raise ValueError("broken")
    except ValueError:
        get_logger("demo").exception("failed")
    assert "ValueError" in read_json_lines(destination)[0]["exception"]


def test_third_party_loggers_are_quietened(tmp_path: Path, config: Config) -> None:
    """Libraries that report the same thing in their own format are quietened.

    azure-identity logs a token failure and we then explain it. The server
    frameworks announce startup and we already log that as a JSON line. One
    report, in one format, on one stream.
    """
    configure_logging(config, surface="cli")
    for name in ("azure.identity", "fastmcp", "uvicorn"):
        assert logging.getLogger(name).level >= logging.WARNING


def test_verbose_restores_the_third_party_loggers(config: Config) -> None:
    """Debugging a dependency needs the dependency's own account of itself."""
    configure_logging(config, surface="cli", level="DEBUG")
    assert logging.getLogger("azure.identity").level == logging.DEBUG
