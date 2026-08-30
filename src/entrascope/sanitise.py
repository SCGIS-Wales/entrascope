"""Making somebody else's text safe to emit.

A display name, a failure message from an API and an identifier typed at a
prompt are all text this tool did not write, and all of them reach a terminal,
a log stream or a query. The rules for making each safe are small, they are the
same rules in several places, and getting one of them wrong is a security bug
rather than a cosmetic one, so they live here once.

Nothing in this module imports anything but the standard library, so every
other module can use it without a cycle.
"""

from __future__ import annotations

import re

#: Every control character, including tab and newline. Used where a value must
#: occupy exactly one field of one line: a query filter, an identifier, a log
#: message. A newline in one of those forges a record and an escape sequence is
#: obeyed by whatever prints it.
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")

#: Every control character except tab and newline, which are left alone where a
#: value is prose that a table may legitimately wrap over several lines.
CONTROL_EXCEPT_WHITESPACE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def strip_control(value: str) -> str:
    """Remove control characters, keeping tab and newline.

    For prose shown in a table, where a line break is a line break and nothing
    worse. An escape sequence is still removed, because a terminal obeys one.
    """
    return CONTROL_EXCEPT_WHITESPACE.sub("", value)


def one_line(value: str) -> str:
    """Return a value that cannot be anything but one line.

    A tab and a newline become spaces rather than disappearing, so that words
    either side of one do not run together, and every other control character
    is removed. This is what a log line, a table cell in the plain format and a
    row of the live view each need: a value that cannot forge a record or move
    a cursor.
    """
    return CONTROL_CHARACTERS.sub(
        "", value.replace("\t", " ").replace("\n", " ").replace("\r", " ")
    )


def bounded(value: str, limit: int) -> str:
    """Return a value with its control characters gone and its length capped.

    For anything substituted into a query. A value longer than a name or an
    identifier could be is a mistake or an attack, and neither is worth
    sending.
    """
    return CONTROL_CHARACTERS.sub("", value)[:limit]
