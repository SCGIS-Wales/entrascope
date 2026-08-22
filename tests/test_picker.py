"""Chooser tests, driven through a stub screen rather than a real terminal."""

from __future__ import annotations

import curses
from typing import Any

import pytest

from entrascope.picker import Choice, available, choose, run, visible


# framework contract: curses passes a window object to the callback, so the
# double must answer the same handful of calls.
class Screen:
    """A screen that records what was drawn and replays scripted key presses."""

    def __init__(self, keys: list[int], height: int = 10, width: int = 60) -> None:
        self.keys = list(keys)
        self.size = (height, width)
        self.drawn: list[str] = []

    def getmaxyx(self) -> tuple[int, int]:
        return self.size

    def erase(self) -> None:
        self.drawn.clear()

    def addnstr(
        self, row: int, column: int, text: str, width: int, style: int = 0
    ) -> None:
        _ = row, column, width, style
        self.drawn.append(text)

    def refresh(self) -> None:
        return None

    def getch(self) -> int:
        return self.keys.pop(0) if self.keys else ord("q")


def choices() -> list[Choice]:
    """Return a handful of lines to choose from."""
    return [
        Choice(key="a1", label="Alpha application"),
        Choice(key="b2", label="Beta application"),
        Choice(key="c3", label="Gamma service"),
    ]


def test_a_line_matches_its_label_or_its_key() -> None:
    """A search term may be a name or an identifier."""
    line = Choice(key="6fb17f1c", label="AWS Agent Smoke Test")
    assert line.matches("aws")
    assert line.matches("6FB17")
    assert not line.matches("nothing")


def test_filtering_narrows_the_list() -> None:
    """A search shows only what matches, and no search shows everything."""
    assert len(visible(choices(), "")) == 3
    assert len(visible(choices(), "application")) == 2
    assert visible(choices(), "gamma")[0].key == "c3"


def test_moving_and_selecting() -> None:
    """Down then enter picks the second line."""
    screen = Screen([curses.KEY_DOWN, 10])
    assert run(screen, choices(), "Choose") == "b2"


def test_vi_keys_move_as_well() -> None:
    """j and k do what the arrow keys do."""
    assert run(Screen([ord("j"), ord("j"), 10]), choices(), "Choose") == "c3"
    assert run(Screen([ord("j"), ord("k"), 10]), choices(), "Choose") == "a1"


def test_searching_with_a_slash() -> None:
    """Slash starts a search, the term filters, and enter selects the match."""
    keys = [ord("/"), ord("g"), ord("a"), ord("m"), 10, 10]
    assert run(Screen(keys), choices(), "Choose") == "c3"


def test_a_search_can_be_abandoned() -> None:
    """Escape clears the term and leaves the whole list."""
    keys = [ord("/"), ord("z"), 27, 10]
    assert run(Screen(keys), choices(), "Choose") == "a1"


def test_backspace_corrects_a_search() -> None:
    """A mistyped term can be corrected rather than restarted."""
    keys = [ord("/"), ord("g"), ord("z"), curses.KEY_BACKSPACE, ord("a"), 10, 10]
    assert run(Screen(keys), choices(), "Choose") == "c3"


def test_quitting_returns_nothing() -> None:
    """Deciding against it is not an error."""
    assert run(Screen([ord("q")]), choices(), "Choose") is None
    assert run(Screen([27]), choices(), "Choose") is None


def test_paging_moves_further() -> None:
    """Page down goes past the end without falling off it."""
    assert run(Screen([curses.KEY_NPAGE, 10]), choices(), "Choose") == "c3"
    assert run(Screen([curses.KEY_PPAGE, 10]), choices(), "Choose") == "a1"


def test_the_help_line_is_always_drawn() -> None:
    """A chooser nobody can drive is no use."""
    screen = Screen([ord("q")])
    run(screen, choices(), "Choose")
    assert any("enter to open" in line for line in screen.drawn)


def test_there_is_no_chooser_without_a_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Piped output or a test run gets no chooser, and the caller carries on."""
    monkeypatch.setattr("entrascope.picker.available", lambda: False)
    assert choose(choices()) is None
    assert choose([]) is None


def test_availability_needs_both_streams(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drawing needs a terminal to read from as well as one to write to."""

    class Stream:
        def __init__(self, terminal: bool) -> None:
            self.terminal = terminal

        def isatty(self) -> bool:
            return self.terminal

    monkeypatch.setattr("entrascope.picker.sys.stdin", Stream(True))
    monkeypatch.setattr("entrascope.picker.sys.stdout", Stream(False))
    assert not available()
    monkeypatch.setattr("entrascope.picker.sys.stdout", Stream(True))
    assert available()


def test_a_drawing_failure_is_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    """A terminal that cannot be driven falls back rather than failing."""

    def explode(*args: Any, **kwargs: Any) -> None:
        raise curses.error("no")

    monkeypatch.setattr("entrascope.picker.available", lambda: True)
    monkeypatch.setattr("entrascope.picker.curses.wrapper", explode)
    assert choose(choices()) is None
