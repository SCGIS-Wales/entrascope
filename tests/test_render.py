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


def in_zone(config: Config, zone: str) -> Config:
    """Return the configuration with timestamps shown in one zone."""
    display = config.fields.display
    timestamp = display.timestamp.model_copy(update={"zone": zone})
    return config.model_copy(
        update={
            "fields": config.fields.model_copy(
                update={"display": display.model_copy(update={"timestamp": timestamp})}
            )
        }
    )


def test_timestamps_are_trimmed_and_named(config: Config) -> None:
    """Two decimal places, and the zone said out loud."""
    from entrascope.render import format_timestamp

    config = in_zone(config, "utc")
    assert format_timestamp("2026-08-22T13:24:32.7891111Z", config) == (
        "2026-08-22 13:24:32.79 UTC"
    )
    assert format_timestamp("2026-08-22T13:24:32Z", config).endswith("UTC")
    assert format_timestamp("not a timestamp", config) == "not a timestamp"


def test_an_offset_timestamp_is_converted(config: Config) -> None:
    """A timestamp with an offset is shown in the configured zone."""
    from entrascope.render import format_timestamp

    config = in_zone(config, "utc")
    assert format_timestamp("2026-08-22T13:24:32.78+01:00", config).startswith(
        "2026-08-22 12:24:32.78"
    )


def test_timestamps_can_be_shown_in_the_local_zone(config: Config) -> None:
    """The zone is named whichever one is chosen, so nothing is ambiguous."""
    from entrascope.render import format_timestamp

    rendered = format_timestamp("2026-08-22T13:24:32.78Z", in_zone(config, "local"))
    assert rendered.count(":") == 2
    assert rendered.split()[-1]


def test_a_guest_account_is_trimmed_for_reading(config: Config) -> None:
    """The home tenant address is half a column that says nothing."""
    from entrascope.render import shorten_guest

    whole = "someone_example.com#EXT#@tenant.onmicrosoft.com"
    assert shorten_guest(whole, config) == "someone_example.com"
    assert shorten_guest("someone@example.invalid", config) == "someone@example.invalid"


def test_the_plain_format_is_tab_separated_and_complete(config: Config) -> None:
    """The format to grep, to paste and to pipe. Nothing truncated."""
    rows = [Row(name="one", count=2, tags=("a", "b"))]
    text = render(rows, config, "plain")
    header, line = text.splitlines()
    assert header.split("\t")[:2] == ["name", "count"]
    assert line.split("\t")[0] == "one"


def test_the_plain_format_never_breaks_a_record_across_lines(
    config: Config,
) -> None:
    """One line is one record, whatever the values contain."""
    rows = [{"a": "has\ttab", "b": "plain"}]
    line = render(rows, config, "plain").splitlines()[1]
    assert line.count("\t") == 1


def test_a_list_of_objects_is_summarised_in_a_table(config: Config) -> None:
    """A cell full of JSON tells the reader nothing and costs the whole line."""
    from entrascope.render import cell

    credentials = [{"state": "valid"}, {"state": "expired"}, {"state": "expired"}]
    assert cell(credentials, config) == "3: 2 expired, 1 valid"
    assert cell([{"nothing": 1}], config) == "1 items"


def test_an_empty_cell_is_marked(config: Config) -> None:
    """A blank cell looks like a broken column. A dash does not."""
    from entrascope.render import EMPTY_CELL, cell

    assert cell(None, config) == EMPTY_CELL
    assert cell("", config) == EMPTY_CELL
    assert cell([], config) == EMPTY_CELL


def test_a_table_has_no_box_drawing(config: Config) -> None:
    """Box drawing cannot be pasted into a ticket and reads worse at length."""
    text = render([Row(name="one", count=2)], config, "table")
    for character in "┏┃┡│└┘├":
        assert character not in text


def test_a_piped_table_is_not_truncated(config: Config) -> None:
    """Writing a table to a file must not lose characters to a guessed width."""
    long_name = "a" * 120
    text = render([Row(name=long_name, count=1)], config, "table")
    assert long_name in text


def test_short_columns_keep_their_width(config: Config) -> None:
    """An identifier somebody has to type is no use half printed."""
    from entrascope.render import guaranteed_widths

    granted = guaranteed_widths({"kind": 18, "detail": 400}, {"detail"}, 120)
    assert granted == {"kind": 18}


def test_guaranteed_widths_stay_inside_their_budget(config: Config) -> None:
    """Guaranteeing everything would push the last columns off the line."""
    from entrascope.render import guaranteed_widths

    widths = {f"column{index}": 25 for index in range(10)}
    granted = guaranteed_widths(widths, set(), 100)
    assert sum(granted.values()) <= 60


def test_a_count_summary_reads_like_a_person_wrote_it() -> None:
    """One row is not one rows."""
    from entrascope.render import count_summary

    assert count_summary([1], "audit events") == "1 audit event"
    assert count_summary([1, 2], "audit events") == "2 audit events"


def test_severity_and_outcome_are_coloured(config: Config) -> None:
    """Colour where colour means something, and nowhere else."""
    from entrascope.render import colour_for

    assert colour_for("error", config)
    assert colour_for("FAIL", config)
    assert colour_for("success", config)
    assert colour_for("Update application", config) == ""


def test_a_terminal_escape_in_directory_data_is_removed(config: Config) -> None:
    """A display name is somebody else's input, and a terminal obeys escapes."""
    from entrascope.render import cell, render_plain

    assert cell("name\x1b[31mred\x1b[0m", config) == "name[31mred[0m"
    line = render_plain([{"a": "x\x1b]0;title\x07y"}], config).splitlines()[1]
    assert "\x1b" not in line
    assert "\x07" not in line


def test_a_newline_in_a_value_cannot_forge_a_row(config: Config) -> None:
    """One line is one record in the plain format, whatever a value contains."""
    from entrascope.render import render_plain

    rendered = render_plain([{"a": "one\ntwo", "b": "three"}], config)
    assert len(rendered.splitlines()) == 2
