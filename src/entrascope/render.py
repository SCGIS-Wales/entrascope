"""Rendering and exit codes.

One renderer, shared by the command line and the MCP tool surface, so that an
MCP tool result and a CLI ``--output json`` payload are the same bytes rather
than two implementations that drift apart.

Four formats, each for a different reader:

- ``table``, for a person at a terminal. Aligned columns, no box drawing,
  colour where colour means something, and one row per line so that a screen of
  output can still be read.
- ``plain``, tab separated with a header. This is the one to pipe into grep,
  awk or a spreadsheet, and the one to paste into a ticket.
- ``json`` and ``yaml``, for a machine, carrying every field exactly as
  Microsoft Graph gave it.

This is also the only module permitted to write to a terminal.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, tzinfo
from typing import Any, Literal, TextIO

import click
import yaml
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from entrascope.config import Config
from entrascope.logger import handed_to
from entrascope.redaction import redact_with_config
from entrascope.sanitise import one_line, strip_control

#: The output formats every command supports.
OutputFormat = Literal["table", "plain", "json", "yaml"]

OUTPUT_FORMATS: tuple[OutputFormat, ...] = ("table", "plain", "json", "yaml")

#: Exit codes, in one place, shared by every command.
EXIT_OK = 0
EXIT_CHECKS_FAILED = 1
EXIT_CREDENTIALS = 2
EXIT_API = 3
EXIT_CONFIG = 4
#: 128 plus SIGINT, which is what a shell expects from an interrupted process.
EXIT_INTERRUPTED = 130

#: Marks in a check report, chosen to read the same in a pipe as on a terminal.
PASS_MARK = "pass"
FAIL_MARK = "FAIL"

#: Separator for the plain format. A tab survives copy and paste and is what
#: cut and awk expect.
PLAIN_SEPARATOR = "\t"

#: Written in a cell that has no value, so a column never looks misaligned.
EMPTY_CELL = "-"

#: Width used when the destination is not a terminal and says nothing about how
#: wide it is. A table written to a file or a pipe must not lose characters to a
#: guess of eighty columns.
PIPED_WIDTH = 240

#: A column no wider than this may be given its full width rather than elided.
NARROW_COLUMN = 30

#: The share of the width that guaranteed columns may take between them. The
#: rest is left for the columns that carry prose, which can wrap.
GUARANTEED_SHARE = 0.6


def column_widths(
    rows: Sequence[Any], names: Sequence[str], config: Config
) -> dict[str, int]:
    """Return the widest rendered value in each column, including the heading."""
    widths = {name: len(name) for name in names}
    for row in rows:
        payload = payload_for(row, config)
        if not isinstance(payload, Mapping):
            continue
        for name in names:
            widths[name] = max(widths[name], len(cell(payload.get(name), config)))
    return widths


def guaranteed_widths(
    widths: Mapping[str, int], wrapping: set[str], available: int
) -> dict[str, int]:
    """Decide which columns keep their full width.

    A short column holding an identifier is no use half printed, so it is given
    the room it needs. The narrowest are granted first, and only while a share
    of the line remains, because guaranteeing everything would push the last
    columns off the end entirely.
    """
    budget = int(available * GUARANTEED_SHARE)
    granted: dict[str, int] = {}
    candidates = sorted(
        ((name, width) for name, width in widths.items() if name not in wrapping),
        key=lambda pair: pair[1],
    )
    for name, width in candidates:
        if width > NARROW_COLUMN or width > budget:
            continue
        granted[name] = width
        budget -= width
    return granted


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


#: A Graph timestamp, which may carry any number of fractional digits.
TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)


def zone_for(config: Config) -> tzinfo:
    """Return the zone timestamps are shown in."""
    if config.fields.display.timestamp.zone == "local":
        return datetime.now().astimezone().tzinfo or UTC
    return UTC


def format_timestamp(value: str, config: Config) -> str:
    """Render a Graph timestamp for a person, with its zone named.

    Graph reports to the nanosecond in UTC. Nine decimal places cost a third of
    the column and settle nothing, and a timestamp with no zone on it invites
    the wrong conclusion, so the zone is always named.
    """
    settings = config.fields.display.timestamp
    match = TIMESTAMP.match(value)
    if match is None:
        return value
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    shown = moment.astimezone(zone_for(config))
    stamp = shown.strftime("%Y-%m-%d %H:%M:%S")
    if settings.decimals > 0:
        fraction = f"{shown.microsecond / 1_000_000:.{settings.decimals}f}"
        stamp = f"{stamp}{fraction[1:]}"
    return f"{stamp} {shown.strftime('%Z') or 'UTC'}"


def cell(value: Any, config: Config) -> str:
    """Render one value for a person to read."""
    if value is None or value == "":
        return EMPTY_CELL
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, Mapping):
        return json.dumps(value, default=str)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        if value and all(isinstance(item, Mapping) for item in value):
            return summarise(value, config)
        rendered = ", ".join(cell(item, config) for item in value)
        return rendered or EMPTY_CELL
    if isinstance(value, str):
        return strip_control(shorten_guest(format_timestamp(value, config), config))
    return str(value)


def flatten(value: str) -> str:
    """Return a value fit for one field of one line.

    In the plain format a line is a record, so a newline or a tab inside a
    value would forge a row or a column. Prose keeps its newlines in a table,
    where they are only a line break, which is what strip_control leaves alone.
    """
    return one_line(value)


def shorten_guest(value: str, config: Config) -> str:
    """Trim a guest account to the part that names the person.

    A guest is reported as their whole home tenant address, which is half a
    column of characters that say nothing the reader did not already know. The
    full value is kept in every machine readable format.
    """
    marker = config.fields.display.guest_marker
    if marker and marker in value:
        return value.split(marker)[0]
    return value


#: Keys whose values are worth tallying when a cell holds a list of objects.
TALLY_KEYS = ("state", "severity", "result", "kind", "type")


def summarise(items: Sequence[Any], config: Config) -> str:
    """Summarise a list of objects for a table cell.

    A cell holding the JSON of three credentials tells the reader nothing and
    costs the whole line. A count, and a tally of whatever distinguishes them,
    tells them whether to look closer. The objects themselves are in every
    machine readable format.
    """
    _ = config
    key = next((name for name in TALLY_KEYS if any(name in item for item in items)), "")
    if not key:
        return f"{len(items)} items"
    tally: dict[str, int] = {}
    for item in items:
        value = str(item.get(key, "")) or "unknown"
        tally[value] = tally.get(value, 0) + 1
    parts = ", ".join(f"{count} {name}" for name, count in sorted(tally.items()))
    return f"{len(items)}: {parts}"


def colour_for(text: str, config: Config) -> str:
    """Return the style for a value whose meaning is worth seeing at a glance."""
    return config.fields.display.colours.get(text, "")


def styled(text: str, config: Config, link: str = "") -> Text:
    """Return a cell, coloured by meaning and linked where there is somewhere to go.

    A terminal that understands hyperlinks makes the value clickable. One that
    does not shows exactly the same characters, and the URL itself is in every
    machine readable format, so nothing depends on the terminal.
    """
    style = colour_for(text, config)
    if link:
        style = f"{style} link {link}".strip()
    return Text(text, style=style)


def portal_link(row: Mapping[str, Any], column: str, config: Config) -> str:
    """Return the portal address for one cell, or an empty string.

    A listing names an object. The next thing anybody wants is to look at it.
    """
    portal = config.endpoints.portal
    if column == "docs_url":
        return str(row.get(column) or "")
    if column in ("target", "target_id"):
        kind = str(row.get("target_type") or "")
        identifier = str(row.get("target_id") or "")
        if not identifier:
            return ""
        if kind.startswith("application"):
            return portal.application_by_object.format(object_id=identifier)
        if kind.startswith("enterprise"):
            return portal.enterprise_application.format(object_id=identifier)
        if kind == "user":
            return portal.user.format(object_id=identifier)
        if kind == "group":
            return portal.group.format(object_id=identifier)
        return ""
    if column in ("display_name", "app_id", "object_id"):
        app_id = str(row.get("app_id") or "")
        object_id = str(row.get("object_id") or "")
        kind = str(row.get("service_principal_type") or "")
        if kind and object_id:
            return portal.enterprise_application.format(object_id=object_id)
        if app_id:
            return portal.application.format(app_id=app_id)
    if column in ("app_display_name", "app_id") and row.get("app_id"):
        return portal.application.format(app_id=str(row["app_id"]))
    return ""


def console_for(stream: TextIO | None = None, record: bool = False) -> Console:
    """Build the console.

    rich decides for itself whether the destination is a terminal, so colour
    appears for a person and disappears in a pipe or a file without anything
    here having to ask. NO_COLOR is honoured because rich honours it.
    """
    # framework contract: rich expresses output as a Console object. It carries
    # presentation only.
    console = Console(
        file=stream or sys.stdout,
        record=record,
        soft_wrap=False,
        highlight=False,
    )
    if not console.is_terminal:
        # A pipe or a file has no width. Leaving rich to guess eighty columns
        # would silently cut characters out of the record. COLUMNS is honoured
        # only for a real terminal, where it means something.
        console.width = PIPED_WIDTH
    return console


def build_table(
    rows: Sequence[Any],
    config: Config,
    *,
    title: str = "",
    columns: Sequence[str] | None = None,
    available: int = 100,
) -> Table:
    """Build a borderless, aligned table.

    No box drawing. A grid of vertical bars cannot be pasted into a ticket, and
    at ninety rows it is harder to read than plain columns. Only prose columns
    wrap; everything else stays on one line and is elided, because a value split
    across four lines can be neither read nor copied.
    """
    names = tuple(columns) if columns else columns_for(rows)
    wrapping = set(config.fields.display.wrapping_columns)
    # framework contract: rich expresses a table as an object, for presentation.
    table = Table(
        title=title or None,
        box=None,
        show_edge=False,
        pad_edge=False,
        title_justify="left",
        title_style="bold",
        header_style="bold",
        padding=(0, 2, 0, 0),
    )
    guaranteed = guaranteed_widths(
        column_widths(rows, names, config), wrapping, available
    )
    for name in names:
        wraps = name in wrapping
        table.add_column(
            name.replace("_", " "),
            overflow="fold" if wraps else "ellipsis",
            no_wrap=not wraps,
            min_width=guaranteed.get(name),
        )
    for row in rows:
        payload = payload_for(row, config)
        if isinstance(payload, Mapping):
            table.add_row(
                *[
                    styled(
                        cell(payload.get(name), config),
                        config,
                        portal_link(payload, name, config),
                    )
                    for name in names
                ]
            )
        else:
            table.add_row(styled(cell(payload, config), config))
    return table


def render_table(
    rows: Sequence[Any],
    config: Config,
    *,
    title: str = "",
    columns: Sequence[str] | None = None,
    width: int | None = None,
) -> str:
    """Render rows as a table and return the text, for a test or a file."""
    console = console_for(record=True)
    console.width = width or console.width
    console.begin_capture()
    console.print(
        build_table(rows, config, title=title, columns=columns, available=console.width)
    )
    return console.end_capture()


def render_plain(
    rows: Sequence[Any],
    config: Config,
    *,
    columns: Sequence[str] | None = None,
) -> str:
    """Render rows as tab separated lines with a header.

    This is the format to pipe, to paste and to grep. Values are never
    truncated and never wrapped, so a line is a record.
    """
    names = tuple(columns) if columns else columns_for(rows)
    if not names:
        return ""
    lines = [PLAIN_SEPARATOR.join(names)]
    for row in rows:
        payload = payload_for(row, config)
        if isinstance(payload, Mapping):
            values = [cell(payload.get(name), config) for name in names]
        else:
            values = [cell(payload, config)]
        lines.append(PLAIN_SEPARATOR.join(flatten(value) for value in values))
    return "\n".join(lines)


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
    if output == "plain":
        return render_plain(rows, config, columns=columns)
    if not rows:
        return f"{title or 'No rows'}: nothing to show."
    return render_table(rows, config, title=title, columns=columns)


def show(
    rows: Sequence[Any],
    config: Config,
    output: OutputFormat = "table",
    *,
    title: str = "",
    columns: Sequence[str] | None = None,
    summary: str = "",
) -> None:
    """Write rows to the terminal in the requested format.

    A table is written through the console rather than rendered to a string
    first, so that colour and the real terminal width are used when there is a
    terminal, and neither when the output is piped.
    """
    if output != "table":
        emit(render(rows, config, output, title=title, columns=columns))
        return
    if not rows:
        emit(f"{title or 'No rows'}: nothing to show.")
        return
    console = console_for()
    console.print(
        build_table(rows, config, title=title, columns=columns, available=console.width)
    )
    if summary:
        console.print(Text(summary, style="dim"))


def render_record(row: Any, config: Config, *, title: str = "") -> str:
    """Render one object as a list of fields, for reading in full.

    A row in a listing is a summary. This is the whole thing, which is what
    somebody who has picked one row out of ninety actually wants.
    """
    payload = payload_for(row, config)
    if not isinstance(payload, Mapping):
        return cell(payload, config)
    width = max((len(str(name)) for name in payload), default=0)
    lines = [f"{title}"] if title else []
    for name, value in payload.items():
        rendered = cell(value, config)
        if isinstance(value, Mapping | list) and value:
            rendered = json.dumps(value, default=str)
        lines.append(f"  {str(name).replace('_', ' '):<{width}}  {rendered}")
    return "\n".join(lines)


def count_summary(rows: Sequence[Any], noun: str) -> str:
    """Return a one line count, so a long listing says how long it was."""
    total = len(rows)
    return f"{total} {noun}" if total != 1 else f"1 {noun.rstrip('s')}"


def yaml_text(payload: Any, config: Config) -> str:
    """Return a payload as YAML, in the order it was built rather than sorted."""
    return yaml.safe_dump(
        payload_for(payload, config),
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=100,
    )


def show_yaml(payload: Any, config: Config, output: OutputFormat = "yaml") -> None:
    """Write a payload as YAML, coloured when there is a terminal to colour.

    A report of this size is far easier to read with its keys picked out, and
    YAML is the shape it already has. Piped, it is exactly the same text with
    no escape codes, so it can be saved or parsed.
    """
    if output == "json":
        emit(json.dumps(payload_for(payload, config), indent=2, default=str))
        return
    text_form = yaml_text(payload, config)
    console = console_for()
    if not console.is_terminal:
        emit(text_form)
        return
    # framework contract: rich expresses highlighting as a Syntax object. It is
    # presentation only, and the text is identical without it.
    console.print(
        Syntax(text_form, "yaml", theme="ansi_dark", background_color="default")
    )


@contextmanager
def working(message: str) -> Iterator[None]:
    """Say what is being done while it is being done.

    A directory of several hundred applications takes a while to read, and a
    tool that says nothing for a minute has, as far as anybody watching is
    concerned, hung. On a terminal this is a spinner that clears itself; piped,
    it is one line so a log still records what was happening.
    """
    console = console_for(sys.stderr)
    if not console.is_terminal:
        console.print(f"{message}...")
        yield
        return
    # framework contract: rich expresses a spinner as a context manager. It is
    # presentation only and the work is unaffected.
    # A log line written straight to the stream lands on top of the spinner,
    # which is how "⠸ Investigating...INFO discovered 383" comes about. Printed
    # through the same console, rich moves the spinner out of the way and the
    # line lands above it where it should.
    with (
        console.status(f"[dim]{message}...[/dim]", spinner="dots"),
        handed_to(
            lambda _, written: console.print(written, markup=False, highlight=False)
        ),
    ):
        yield


def emit(text: str) -> None:
    """Write rendered output. The single place this tool writes to a terminal."""
    click.echo(text.rstrip("\n"))


def emit_error(text: str) -> None:
    """Write a message to standard error."""
    click.echo(text.rstrip("\n"), err=True)


def mark(passed: bool) -> str:
    """Render a check outcome."""
    return PASS_MARK if passed else FAIL_MARK


def check_rows(results: Sequence[Any]) -> list[dict[str, Any]]:
    """Project check results into the columns the report shows."""
    return [
        {
            "outcome": mark(bool(result.passed)),
            "check": result.check,
            "detail": result.detail,
            "remediation": result.remediation,
            "documentation": result.docs_url,
        }
        for result in results
    ]


def render_checks(
    results: Sequence[Any], config: Config, output: OutputFormat = "table"
) -> str:
    """Render preflight check results, which have their own column layout."""
    if output in ("json", "yaml"):
        return render(results, config, output)
    return render(check_rows(results), config, output, title="entrascope doctor")


def show_checks(
    results: Sequence[Any], config: Config, output: OutputFormat = "table"
) -> None:
    """Write the preflight report."""
    if output in ("json", "yaml"):
        emit(render(results, config, output))
        return
    failed = sum(1 for result in results if not result.passed)
    show(
        check_rows(results),
        config,
        output,
        title="entrascope doctor",
        summary=(
            f"{len(results)} checks, {failed} failed"
            if failed
            else f"{len(results)} checks, all passed"
        ),
    )


def exit_code_for_checks(results: Sequence[Any]) -> int:
    """Return the exit code for a set of checks."""
    return EXIT_OK if all(result.passed for result in results) else EXIT_CHECKS_FAILED


def colour_disabled() -> bool:
    """Return whether colour has been switched off in the environment."""
    return bool(os.environ.get("NO_COLOR"))
