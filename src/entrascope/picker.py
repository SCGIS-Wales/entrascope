"""An interactive chooser for a terminal.

A list of ninety applications is not something anybody wants to scroll past and
then retype a name from. This draws the list, moves with the arrow keys or with
j and k, filters with a slash the way vi does, and returns what was chosen.

It uses curses from the standard library, so it adds no dependency. When there
is no terminal, for instance when the output is piped or a test is running, it
declines and the caller falls back to asking for a number.
"""

from __future__ import annotations

import curses
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:  # pragma: no cover
    from curses import window
else:  # pragma: no cover
    window = object

from entrascope.logger import get_logger

log = get_logger(__name__)

#: Keys that move down, up, and leave.
DOWN_KEYS = (curses.KEY_DOWN, ord("j"))
UP_KEYS = (curses.KEY_UP, ord("k"))
QUIT_KEYS = (27, ord("q"))
SELECT_KEYS = (10, 13, curses.KEY_ENTER)
SEARCH_KEYS = (ord("/"),)
BACKSPACE_KEYS = (curses.KEY_BACKSPACE, 127, 8)

#: Shown along the bottom, because a chooser nobody can drive is no use.
HELP_LINE = "  up and down or j k to move, / to search, enter to open, q to stop"


class Choice(NamedTuple):
    """One line in the chooser."""

    key: str
    label: str

    def matches(self, term: str) -> bool:
        """Return whether this line matches a search term."""
        lowered = term.lower()
        return lowered in self.label.lower() or lowered in self.key.lower()


def available() -> bool:
    """Return whether a chooser can be drawn at all."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def visible(choices: Sequence[Choice], term: str) -> list[Choice]:
    """Return the lines matching the current search."""
    if not term:
        return list(choices)
    return [choice for choice in choices if choice.matches(term)]


def draw(
    screen: window,
    choices: Sequence[Choice],
    selected: int,
    term: str,
    title: str,
) -> None:
    """Draw the chooser once."""
    screen.erase()
    height, width = screen.getmaxyx()
    body = max(1, height - 3)
    top = max(0, min(selected - body // 2, max(0, len(choices) - body)))
    heading = f"{title}  ({len(choices)})" if not term else f"{title}  /{term}"
    screen.addnstr(0, 0, heading, width - 1, curses.A_BOLD)
    for offset, choice in enumerate(choices[top : top + body]):
        index = top + offset
        style = curses.A_REVERSE if index == selected else curses.A_NORMAL
        screen.addnstr(offset + 1, 0, f"  {choice.label}", width - 1, style)
    screen.addnstr(height - 1, 0, HELP_LINE, width - 1, curses.A_DIM)
    screen.refresh()


def hide_cursor() -> None:
    """Hide the cursor if the terminal allows it.

    Some terminals refuse, and a chooser that fails because of the cursor
    would be a silly thing to fail on.
    """
    try:
        curses.curs_set(0)
    except curses.error:  # pragma: no cover
        log.debug("this terminal will not hide the cursor")


def run(screen: window, choices: Sequence[Choice], title: str) -> str | None:
    """Drive the chooser until something is picked or it is abandoned."""
    hide_cursor()
    term = ""
    searching = False
    selected = 0
    while True:
        shown = visible(choices, term)
        selected = max(0, min(selected, len(shown) - 1)) if shown else 0
        draw(screen, shown, selected, term, title)
        key = screen.getch()

        if searching:
            if key in SELECT_KEYS:
                searching = False
            elif key in BACKSPACE_KEYS:
                term = term[:-1]
            elif key == 27:
                term, searching = "", False
            elif 32 <= key < 127:
                term += chr(key)
                selected = 0
            continue

        if key in QUIT_KEYS:
            return None
        if key in SEARCH_KEYS:
            searching, term = True, ""
            continue
        if key in DOWN_KEYS:
            selected += 1
        elif key in UP_KEYS:
            selected -= 1
        elif key == curses.KEY_NPAGE:
            selected += 10
        elif key == curses.KEY_PPAGE:
            selected -= 10
        elif key in SELECT_KEYS and shown:
            return shown[selected].key
        elif key in BACKSPACE_KEYS:
            term = ""


def choose(choices: Sequence[Choice], title: str = "Choose") -> str | None:
    """Show the chooser and return the key of what was picked.

    Returns None when there is no terminal, when the list is empty, or when the
    engineer decided against it, so the caller can carry on without one.
    """
    if not choices or not available():
        return None
    try:
        # framework contract: curses takes over the terminal through a wrapper
        # that restores it afterwards, whatever happens.
        return curses.wrapper(run, choices, title)
    except curses.error as error:
        log.debug("could not draw the chooser: %s", error)
        return None
