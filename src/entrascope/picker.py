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
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Literal, NamedTuple

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
SORT_KEYS = (ord("s"),)

#: How far page up and page down move.
PAGE = 10
SELECT_KEYS = (10, 13, curses.KEY_ENTER)
SEARCH_KEYS = (ord("/"),)
BACKSPACE_KEYS = (curses.KEY_BACKSPACE, 127, 8)

#: Shown along the bottom, because a chooser nobody can drive is no use.
HELP_LINE = (
    "  up and down or j k to move, page up and down, / search, s sort, "
    "enter open, q back"
)
SEARCH_LINE = "  type to narrow, up and down still move, enter opens, escape clears"

#: The eight colours every terminal has.
BASE_COLOURS: dict[str, int] = {
    "black": curses.COLOR_BLACK,
    "red": curses.COLOR_RED,
    "green": curses.COLOR_GREEN,
    "yellow": curses.COLOR_YELLOW,
    "blue": curses.COLOR_BLUE,
    "magenta": curses.COLOR_MAGENTA,
    "cyan": curses.COLOR_CYAN,
    "white": curses.COLOR_WHITE,
}

#: Colours worth having on a dark screen that the eight cannot express, each
#: with the nearest of the eight to fall back to. Orange in particular is the
#: colour somebody means when they say orange, and yellow is not it.
WIDE_COLOURS: dict[str, tuple[int, int]] = {
    "orange": (208, curses.COLOR_YELLOW),
    "amber": (214, curses.COLOR_YELLOW),
    "violet": (141, curses.COLOR_MAGENTA),
    "mint": (79, curses.COLOR_GREEN),
    "slate": (245, curses.COLOR_WHITE),
    "grey": (244, curses.COLOR_WHITE),
}

#: The palette the chooser uses when it is handed no configuration, which is
#: only in a test. It matches the shipped configuration.
DEFAULT_SCHEME: dict[str, str] = {
    "background": "black",
    "foreground": "white",
    "highlight": "bright cyan",
    "heading": "bright cyan",
    "hint": "slate",
}
DEFAULT_TONES: dict[str, str] = {
    "danger": "bright red",
    "warning": "amber",
    "oauth": "orange",
    "saml": "violet",
    "quiet": "slate",
}


def colour_number(name: str) -> int:
    """Return the curses colour for a name, or minus one for the default.

    A bright colour is the base one plus eight, and a wider colour needs a
    terminal with more than sixteen. Anything the terminal cannot show falls
    back to the nearest colour it can, so the chooser is never unreadable
    because of how somebody has their terminal set up.
    """
    wanted = name.strip().lower()
    if not wanted or wanted == "terminal":
        return -1
    available_colours = getattr(curses, "COLORS", 8)
    if wanted in WIDE_COLOURS:
        wide, nearest = WIDE_COLOURS[wanted]
        return wide if available_colours > wide else nearest
    bright = wanted.startswith("bright ")
    base = BASE_COLOURS.get(wanted.removeprefix("bright ").strip(), -1)
    if base < 0:
        return -1
    return base + 8 if bright and available_colours >= 16 else base


class Scheme(NamedTuple):
    """The attributes the chooser draws with, once curses has been started."""

    normal: int = curses.A_NORMAL
    heading: int = curses.A_BOLD
    hint: int = curses.A_DIM
    highlight: int = curses.A_REVERSE
    tones: Mapping[str, int] = {}


#: How a line is coloured. Colour carries meaning here rather than decoration,
#: so each tone means one thing and nothing else.
Tone = Literal["", "danger", "warning", "saml", "oauth", "quiet"]


class Choice(NamedTuple):
    """One line in the chooser."""

    key: str
    label: str
    #: What the line means, which decides its colour.
    tone: Tone = ""
    #: When the thing was created, for sorting by age.
    created: str = ""
    #: The name on its own, for sorting by name.
    name: str = ""

    def matches(self, term: str) -> bool:
        """Return whether this line matches a search term."""
        lowered = term.lower()
        return lowered in self.label.lower() or lowered in self.key.lower()


#: The orders a list can be put in, cycled with s.
ORDERS: tuple[str, ...] = ("name", "name reversed", "newest", "oldest")


def ordered(choices: Sequence[Choice], order: str) -> list[Choice]:
    """Return the lines in one of the orders somebody can ask for."""
    rows = list(choices)
    if order == "name":
        return sorted(rows, key=lambda item: (item.name or item.label).lower())
    if order == "name reversed":
        return sorted(
            rows, key=lambda item: (item.name or item.label).lower(), reverse=True
        )
    if order == "newest":
        return sorted(rows, key=lambda item: item.created, reverse=True)
    return sorted(rows, key=lambda item: item.created)


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
    *,
    searching: bool = False,
    total: int = 0,
    scheme: Scheme | None = None,
) -> None:
    """Draw the chooser once.

    While a search is being typed the heading is the search itself, with a
    cursor. Without that there is nothing to say the slash was registered, and
    the natural response is to press it again, which puts a slash in the term
    and makes the search match nothing.
    """
    screen.erase()
    height, width = screen.getmaxyx()
    body = max(1, height - 3)
    top = max(0, min(selected - body // 2, max(0, len(choices) - body)))
    heading = (
        f"Search: {term}\u258f    {len(choices)} of {total} match"
        if searching
        else f"{title}  ({len(choices)})"
        if not term
        else f"{title}  ({len(choices)} matching {term!r})"
    )
    palette = scheme or Scheme()
    screen.addnstr(0, 0, heading.ljust(width - 1), width - 1, palette.heading)
    for offset, choice in enumerate(choices[top : top + body]):
        index = top + offset
        style = (
            palette.highlight
            if index == selected
            else palette.tones.get(choice.tone, palette.normal)
        )
        line = f"  {choice.label}"
        # The line is padded so the colour under the cursor runs the width of
        # the screen rather than stopping raggedly after the text.
        screen.addnstr(offset + 1, 0, line.ljust(width - 1), width - 1, style)
    footer = SEARCH_LINE if searching else HELP_LINE
    screen.addnstr(height - 1, 0, footer.ljust(width - 1), width - 1, palette.hint)
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


def start_colour(
    screen: window,
    scheme: Mapping[str, str] | None = None,
    tones: Mapping[str, str] | None = None,
) -> Scheme:
    """Set up the colour pairs and return the attributes to draw with.

    The chooser paints its own background rather than borrowing the one the
    terminal happens to have, so the colours are read against the background
    they were chosen for. A terminal without colour gets bold, dim and reverse,
    which say the same things in a plainer way.
    """
    wanted = {**DEFAULT_SCHEME, **(scheme or {})}
    meanings = {**DEFAULT_TONES, **(tones or {})}
    try:
        curses.start_color()
        curses.use_default_colors()
    except curses.error:  # pragma: no cover
        return Scheme()
    background = colour_number(wanted.get("background", ""))
    foreground = colour_number(wanted.get("foreground", ""))

    def pair(index: int, colour: int) -> int:
        try:
            curses.init_pair(index, colour, background)
        except curses.error:  # pragma: no cover
            return 0
        return curses.color_pair(index)

    normal = pair(1, foreground)
    heading = pair(2, colour_number(wanted.get("heading", ""))) | curses.A_BOLD
    hint = pair(3, colour_number(wanted.get("hint", "")))
    highlight = pair(4, colour_number(wanted.get("highlight", ""))) | curses.A_REVERSE
    attributes = {
        tone: pair(index, colour_number(colour))
        for index, (tone, colour) in enumerate(meanings.items(), start=5)
    }
    try:
        screen.bkgd(" ", normal)
    except curses.error:  # pragma: no cover
        log.debug("this terminal will not paint the background")
    return Scheme(
        normal=normal,
        heading=heading,
        hint=hint,
        highlight=highlight,
        tones=attributes,
    )


def run(
    screen: window,
    choices: Sequence[Choice],
    title: str,
    scheme: Mapping[str, str] | None = None,
    tones: Mapping[str, str] | None = None,
) -> str | None:
    """Drive the chooser until something is picked or it is abandoned.

    Moving works while a search is being typed. Somebody who has narrowed a
    list of five hundred to two wants to choose one of them, and being made to
    press enter first before the arrows do anything is the sort of thing that
    reads as broken.
    """
    hide_cursor()
    palette = start_colour(screen, scheme, tones)
    term = ""
    searching = False
    selected = 0
    order = ORDERS[0]
    while True:
        shown = visible(ordered(choices, order), term)
        selected = max(0, min(selected, len(shown) - 1)) if shown else 0
        draw(
            screen,
            shown,
            selected,
            term,
            f"{title}  [{order}]",
            searching=searching,
            total=len(choices),
            scheme=palette,
        )
        key = screen.getch()

        # Movement works the same whether or not a search is being typed.
        if (key in DOWN_KEYS and not searching) or key == curses.KEY_DOWN:
            selected += 1
            continue
        if (key in UP_KEYS and not searching) or key == curses.KEY_UP:
            selected -= 1
            continue
        if key == curses.KEY_NPAGE:
            selected += PAGE
            continue
        if key == curses.KEY_PPAGE:
            selected -= PAGE
            continue
        if key in SELECT_KEYS:
            if shown:
                return shown[selected].key
            searching = False
            continue

        if searching:
            if key in BACKSPACE_KEYS:
                term = term[:-1]
            elif key == 27:
                term, searching = "", False
            elif 32 <= key < 127:
                character = chr(key)
                # A slash typed as the first character is somebody pressing it
                # twice because nothing told them the first one worked. It can
                # only have been meant as the search key.
                if not (character == "/" and not term):
                    term += character
                selected = 0
            continue

        if key in QUIT_KEYS:
            return None
        if key in SEARCH_KEYS:
            searching, term = True, ""
            continue
        if key in SORT_KEYS:
            order = ORDERS[(ORDERS.index(order) + 1) % len(ORDERS)]
            selected = 0
            continue
        if key in BACKSPACE_KEYS:
            term = ""


def choose(
    choices: Sequence[Choice],
    title: str = "Choose",
    scheme: Mapping[str, str] | None = None,
    tones: Mapping[str, str] | None = None,
) -> str | None:
    """Show the chooser and return the key of what was picked.

    Returns None when there is no terminal, when the list is empty, or when the
    engineer decided against it, so the caller can carry on without one.
    """
    if not choices or not available():
        return None
    try:
        # framework contract: curses takes over the terminal through a wrapper
        # that restores it afterwards, whatever happens.
        return curses.wrapper(run, choices, title, scheme, tones)
    except curses.error as error:
        log.debug("could not draw the chooser: %s", error)
        return None
