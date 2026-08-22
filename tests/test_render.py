"""Rendering, payload conversion and exit code tests."""

from __future__ import annotations

import json
from typing import NamedTuple

import pytest
import yaml

from entrascope.config import Config
from entrascope.models import CheckResult
from entrascope.render import (
    EXIT_CHECKS_FAILED,
    EXIT_OK,
    OUTPUT_FORMATS,
    columns_for,
    exit_code_for_checks,
    payload_for,
    render,
    render_checks,
    to_payload,
)
from tests.conftest import SENTINEL_SECRET


class Row(NamedTuple):
    """A data transfer object standing in for a projected result."""

    name: str
    count: int
    tags: tuple[str, ...] = ()
    nested: dict[str, str] | None = None


def test_named_tuples_become_mappings() -> None:
    """A data transfer object converts to a mapping keyed by field name."""
    payload = to_payload(Row(name="one", count=2, tags=("a", "b")))
    assert payload == {"name": "one", "count": 2, "tags": ["a", "b"], "nested": None}


def test_conversion_walks_nested_structures() -> None:
    """Objects inside sequences inside mappings all convert."""
    payload = to_payload({"rows": [Row(name="a", count=1)]})
    assert payload["rows"][0]["name"] == "a"


def test_the_payload_is_redacted(config: Config) -> None:
    """Anything leaving the process passes through redaction."""
    payload = payload_for({"Secret": SENTINEL_SECRET, "ok": 1}, config)
    assert SENTINEL_SECRET not in json.dumps(payload)


def test_json_output_is_valid_and_indented(config: Config) -> None:
    """The JSON form parses and is readable."""
    text = render([Row(name="one", count=2)], config, "json")
    assert json.loads(text)[0]["name"] == "one"


def test_yaml_output_is_valid(config: Config) -> None:
    """The YAML form parses."""
    text = render([Row(name="one", count=2)], config, "yaml")
    assert yaml.safe_load(text)[0]["count"] == 2


def test_table_output_carries_the_columns_and_values(config: Config) -> None:
    """A table names its columns and shows its values."""
    text = render([Row(name="one", count=2)], config, "table", title="Rows")
    assert "Rows" in text
    assert "name" in text
    assert "one" in text


def test_an_empty_result_says_so_rather_than_drawing_an_empty_table(
    config: Config,
) -> None:
    """Nothing to show is stated plainly."""
    assert "nothing to show" in render([], config, "table", title="Applications")


def test_an_empty_result_is_still_valid_json(config: Config) -> None:
    """A machine reading the output gets an empty list, not prose."""
    assert json.loads(render([], config, "json")) == []


def test_every_format_is_supported(config: Config) -> None:
    """Each declared format renders."""
    for output in OUTPUT_FORMATS:
        assert render([Row(name="one", count=2)], config, output)


def test_columns_are_derived_from_the_first_row() -> None:
    """Columns come from the data transfer object, or from a mapping."""
    assert columns_for([Row(name="a", count=1)])[0] == "name"
    assert columns_for([{"x": 1}]) == ("x",)
    assert columns_for([]) == ()
    assert columns_for(["plain"]) == ("value",)


def test_sequences_and_booleans_render_readably(config: Config) -> None:
    """A tuple becomes a list, and a boolean becomes yes or no."""
    text = render([{"tags": ["a", "b"], "enabled": True}], config, "table")
    assert "a, b" in text
    assert "yes" in text


def test_checks_render_with_their_remediation(config: Config) -> None:
    """A failed check shows its remediation and its documentation link."""
    results = [
        CheckResult(check="one", passed=True, detail="fine"),
        CheckResult(
            check="two",
            passed=False,
            detail="broken",
            remediation="chmod 0600 the file",
            docs_url="https://learn.microsoft.com/en-us/entra/",
        ),
    ]
    text = render_checks(results, config)
    assert "pass" in text
    assert "FAIL" in text
    assert "chmod 0600" in text


def test_checks_render_as_json_too(config: Config) -> None:
    """The machine readable report carries the same information."""
    results = [CheckResult(check="one", passed=False, detail="broken")]
    payload = json.loads(render_checks(results, config, "json"))
    assert payload[0]["passed"] is False


def test_exit_code_follows_the_checks() -> None:
    """Any failed check makes the exit code non zero."""
    assert exit_code_for_checks([CheckResult("a", True, "")]) == EXIT_OK
    assert (
        exit_code_for_checks([CheckResult("a", True, ""), CheckResult("b", False, "")])
        == EXIT_CHECKS_FAILED
    )


def test_rendering_a_table_writes_nothing_by_itself(
    config: Config, capsys: pytest.CaptureFixture[str]
) -> None:
    """The renderer returns text and prints nothing.

    Rendering and writing are separate, and a renderer that also printed would
    show every table twice.
    """
    render([Row(name="one", count=2)], config, "table")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
