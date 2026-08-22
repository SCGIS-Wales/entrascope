"""Rendering and exit codes.

One renderer, shared by the command line and the MCP tool surface, so that an
MCP tool result and a CLI ``--output json`` payload are the same bytes rather
than two implementations that drift apart.

This is also the only module permitted to write to a terminal.
"""

from __future__ import annotations

import io
import json
from collections.abc import Mapping, Sequence
from typing import Any, Literal

import click
import yaml
from rich.console import Console
from rich.table import Table

from entrascope.config import Config
from entrascope.redaction import redact_with_config

#: The output formats every command supports.
OutputFormat = Literal["table", "json", "yaml"]

OUTPUT_FORMATS: tuple[OutputFormat, ...] = ("table", "json", "yaml")

#: Exit codes, in one place, shared by every command.
EXIT_OK = 0
EXIT_CHECKS_FAILED = 1
EXIT_CREDENTIALS = 2
EXIT_API = 3
EXIT_CONFIG = 4

#: Marks in a table, chosen to read the same in a pipe as on a terminal.
PASS_MARK = "pass"
FAIL_MARK = "FAIL"


def to_payload(value: Any) -> Any:
    """Convert data transfer objects into plain JSON serialisable structures.

    NamedTuple instances become mappings keyed by field name, which is what both
    the JSON output and the MCP structured content need.
    """
    fields = getattr(value, "_fields", None)
    if fields is not None and isinstance(value, tuple):
        return {
            name: to_payload(item) for name, item in zip(fields, value, strict=True)
        }
    if isinstance(value, Mapping):
        return {str(key): to_payload(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return [to_payload(item) for item in value]
    return value


def payload_for(value: Any, config: Config) -> Any:
    """Convert to a payload and redact it, which is what leaves the process."""
    return redact_with_config(to_payload(value), config)


def columns_for(rows: Sequence[Any]) -> tuple[str, ...]:
    """Return the column names of a sequence of data transfer objects."""
    if not rows:
        return ()
    fields = getattr(rows[0], "_fields", None)
    if fields is not None:
        return tuple(str(name) for name in fields)
    if isinstance(rows[0], Mapping):
        return tuple(str(key) for key in rows[0])
    return ("value",)


def cell(value: Any) -> str:
    """Render one value for a table cell."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, Mapping):
        return json.dumps(value, default=str)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return ", ".join(cell(item) for item in value)
    return str(value)


def render_table(
    rows: Sequence[Any],
    config: Config,
    *,
    title: str = "",
    columns: Sequence[str] | None = None,
    width: int | None = None,
) -> str:
    """Render rows as a table for a person to read."""
    names = tuple(columns) if columns else columns_for(rows)
    # framework contract: rich expresses a table as an object. It is used for
    # presentation only and carries none of our logic.
    table = Table(title=title or None, show_lines=False)
    for name in names:
        table.add_column(name.replace("_", " "), overflow="fold")
    for row in rows:
        payload = payload_for(row, config)
        if isinstance(payload, Mapping):
            table.add_row(*[cell(payload.get(name)) for name in names])
        else:
            table.add_row(cell(payload))
    # The console writes into a buffer rather than to the terminal. Printing
    # here as well as returning the text would render every table twice.
    console = Console(
        record=True, width=width or 200, no_color=True, file=io.StringIO()
    )
    console.print(table)
    return console.export_text()


def render(
    rows: Sequence[Any],
    config: Config,
    output: OutputFormat = "table",
    *,
    title: str = "",
    columns: Sequence[str] | None = None,
) -> str:
    """Render rows in the requested format.

    The JSON form is the same payload the MCP tool surface returns, which a test
    asserts, so that the two surfaces cannot drift apart.
    """
    if output == "json":
        return json.dumps(payload_for(list(rows), config), indent=2, default=str)
    if output == "yaml":
        payload = payload_for(list(rows), config)
        return yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)
    if not rows:
        return f"{title or 'No rows'}: nothing to show.\n"
    return render_table(rows, config, title=title, columns=columns)


def emit(text: str) -> None:
    """Write rendered output. The single place this tool writes to a terminal."""
    click.echo(text.rstrip("\n"))


def emit_error(text: str) -> None:
    """Write an error message to standard error."""
    click.echo(text.rstrip("\n"), err=True)


def mark(passed: bool) -> str:
    """Render a check outcome."""
    return PASS_MARK if passed else FAIL_MARK


def render_checks(
    results: Sequence[Any], config: Config, output: OutputFormat = "table"
) -> str:
    """Render preflight check results, which have their own column layout."""
    if output != "table":
        return render(results, config, output)
    rows = [
        {
            "outcome": mark(bool(result.passed)),
            "check": result.check,
            "detail": result.detail,
            "remediation": result.remediation,
            "documentation": result.docs_url,
        }
        for result in results
    ]
    return render_table(rows, config, title="entrascope doctor")


def exit_code_for_checks(results: Sequence[Any]) -> int:
    """Return the exit code for a set of checks."""
    return EXIT_OK if all(result.passed for result in results) else EXIT_CHECKS_FAILED
