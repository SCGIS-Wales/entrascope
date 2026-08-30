"""Making somebody else's text safe to emit.

Half of what this tool prints is text it did not write: a display name from a
directory, a failure message from an API, an identifier typed at a prompt. The
rules that make each safe are here, and so are the cases that would be a
security bug rather than a cosmetic one if they stopped holding.
"""

from __future__ import annotations

import io
import logging

from entrascope.config import Config
from entrascope.logger import configure_logging, format_human, format_json, get_logger
from entrascope.sanitise import bounded, one_line, strip_control

#: A display name that tries to forge a log line and colour the forgery. A
#: tenant administrator chooses display names, and on the remote server so does
#: anybody whose applications this tool is pointed at.
HOSTILE = "Payroll\nERROR    [00000000] tenant compromised\ttrailing\x1b[31m\x00"


def test_one_line_cannot_be_more_than_one_line() -> None:
    """A newline in a value would forge a record wherever a line is a record."""
    cleaned = one_line(HOSTILE)
    assert "\n" not in cleaned
    assert "\t" not in cleaned
    assert "\x1b" not in cleaned
    assert "\x00" not in cleaned
    # The words either side of a newline must not run together, or two fields
    # become one word and the line reads as something it is not.
    assert "Payroll ERROR" in cleaned


def test_strip_control_keeps_a_line_break_and_removes_an_escape() -> None:
    """Prose in a table may wrap. It may not move the cursor."""
    cleaned = strip_control("first\nsecond\ttabbed\x1b[2Jcleared")
    assert "\n" in cleaned
    assert "\t" in cleaned
    assert "\x1b" not in cleaned


def test_bounded_caps_the_length_and_strips_everything() -> None:
    """A value longer than a name could be is a mistake or an attack."""
    assert bounded("a" * 500, 10) == "a" * 10
    assert bounded("a\nb\tc", 10) == "abc"


def test_a_display_name_cannot_forge_a_human_log_line(config: Config) -> None:
    """The reader has no way to tell a forged line from a real one."""
    configure_logging(config, surface="cli")
    log = get_logger("entrascope.sanitise_test")
    buffer = io.StringIO()
    handler = logging.getLogger("entrascope").handlers[0]
    original = handler.stream  # type: ignore[attr-defined]
    handler.stream = buffer  # type: ignore[attr-defined]
    try:
        log.info("inspecting %s", HOSTILE)
    finally:
        handler.stream = original  # type: ignore[attr-defined]
    written = buffer.getvalue()
    assert written.count("\n") == 1, written
    assert "\x1b" not in written
    assert "\x00" not in written


def test_the_json_log_line_escapes_what_it_carries() -> None:
    """It has always been safe; a test says so rather than leaving it to luck."""
    record = logging.LogRecord(
        "entrascope.test", logging.INFO, "", 0, "inspecting %s", (HOSTILE,), None
    )
    rendered = format_json(record)
    assert rendered.count("\n") == 0
    assert "\\u001b" in rendered or "\\u001B" in rendered


def test_the_human_log_line_carries_the_context_safely() -> None:
    """A context value comes from the same places the message does."""
    record = logging.LogRecord(
        "entrascope.test", logging.INFO, "", 0, "reading", None, None
    )
    record.tenant_id = "abc\ndef"  # type: ignore[attr-defined]
    assert "\n" not in format_human(record)
