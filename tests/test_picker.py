"""Chooser tests, driven through a stub screen rather than a real terminal."""

from __future__ import annotations

import curses
from typing import Any

import pytest

from entrascope.picker import (
    Choice,
    Scheme,
    available,
    choose,
    colour_number,
    draw,
    run,
    start_colour,
    visible,
)


# framework contract: curses passes a window object to the callback, so the
# double must answer the same handful of calls.
class Screen:
    """A screen that records what was drawn and replays scripted key presses."""

    def __init__(self, keys: list[int], height: int = 10, width: int = 60) -> None:
        self.keys = list(keys)
        self.size = (height, width)
        self.drawn: list[str] = []
        #: Everything ever drawn, because erase clears the current frame and a
        #: test about what was shown along the way needs the whole run.
        self.history: list[str] = []
        #: The background the chooser painted, if it painted one.
        self.background: tuple[str, int] | None = None

    def getmaxyx(self) -> tuple[int, int]:
        return self.size

    def erase(self) -> None:
        self.drawn.clear()

    def addnstr(
        self, row: int, column: int, text: str, width: int, style: int = 0
    ) -> None:
        _ = row, column, width, style
        self.drawn.append(text)
        self.history.append(text)

    def refresh(self) -> None:
        return None

    def bkgd(self, character: str, attribute: int = 0) -> None:
        self.background = (character, attribute)

    def getch(self) -> int:
        # Running out of keys means the chooser did not do what the test
        # expected. Raising turns that into a failure rather than a hang,
        # because in search mode every printable key is a character and none
        # of them ends the loop.
        if not self.keys:
            raise AssertionError(f"the chooser asked for another key: {self.drawn[:1]}")
        return self.keys.pop(0)


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
    assert any("enter open" in line for line in screen.history)


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


def test_a_slash_typed_twice_does_not_end_up_in_the_search() -> None:
    """Nothing said the first one worked, so pressing it again is natural.

    A slash in the term makes every match fail, which reads as a broken search
    rather than a mistyped one.
    """
    keys = [ord("/"), ord("/"), ord("g"), ord("a"), 10, 10]
    assert run(Screen(keys), choices(), "Choose") == "c3"


def test_the_search_is_shown_as_it_is_typed() -> None:
    """Otherwise there is no sign the slash registered."""
    screen = Screen([ord("/"), ord("g"), 27, ord("q")])
    run(screen, choices(), "Choose")
    assert any(line.startswith("Search: g") for line in screen.history)
    assert any("escape clears" in line for line in screen.history)


def test_the_heading_counts_what_matched() -> None:
    """A search that found nothing should say so, not look frozen."""
    screen = Screen([ord("/"), ord("z"), 27, ord("q")])
    run(screen, choices(), "Choose")
    assert any("0 of 3 match" in line for line in screen.history)


def test_moving_works_while_a_search_is_being_typed() -> None:
    """Somebody who has narrowed five hundred to two wants to choose one.

    Being made to press enter before the arrows do anything reads as broken,
    which is exactly how it was reported.
    """
    keys = [ord("/"), ord("a"), curses.KEY_DOWN, 10]
    assert run(Screen(keys), choices(), "Choose") == "b2"


def test_enter_while_searching_opens_the_highlighted_line() -> None:
    """Not merely leaving the search, which is what it used to do."""
    keys = [ord("/"), ord("g"), ord("a"), 10]
    assert run(Screen(keys), choices(), "Choose") == "c3"


def test_the_order_can_be_changed() -> None:
    """Alphabetical is one question. The newest is another."""
    from entrascope.picker import ORDERS, ordered

    rows = [
        Choice(key="a", label="Alpha", name="Alpha", created="2024-01-01"),
        Choice(key="b", label="Beta", name="Beta", created="2026-01-01"),
    ]
    assert [item.key for item in ordered(rows, "name")] == ["a", "b"]
    assert [item.key for item in ordered(rows, "name reversed")] == ["b", "a"]
    assert [item.key for item in ordered(rows, "newest")] == ["b", "a"]
    assert [item.key for item in ordered(rows, "oldest")] == ["a", "b"]
    assert ORDERS[0] == "name"


def test_pressing_s_cycles_the_order() -> None:
    """One key, because a chooser is not a form."""
    screen = Screen([ord("s"), ord("q")])
    run(screen, choices(), "Choose")
    assert any("name reversed" in line for line in screen.history)


def test_a_line_carries_what_it_means() -> None:
    """Colour here is meaning, not decoration."""
    line = Choice(key="a", label="An app", tone="danger")
    assert line.tone == "danger"
    assert Choice(key="b", label="Another").tone == ""


def test_a_colour_name_becomes_a_curses_colour() -> None:
    """The palette is written as names, because a number means nothing."""
    assert colour_number("red") == curses.COLOR_RED
    assert colour_number("") == -1
    assert colour_number("terminal") == -1
    assert colour_number("puce") == -1


def test_a_bright_colour_falls_back_when_the_terminal_is_plain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Eight colours is the floor, and the chooser still reads on it."""
    monkeypatch.setattr(curses, "COLORS", 8, raising=False)
    assert colour_number("bright red") == curses.COLOR_RED
    assert colour_number("orange") == curses.COLOR_YELLOW
    monkeypatch.setattr(curses, "COLORS", 256, raising=False)
    assert colour_number("bright red") == curses.COLOR_RED + 8
    assert colour_number("orange") == 208


def test_the_chooser_paints_its_own_background(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The palette is chosen for a dark screen, so the screen is made dark."""
    pairs: dict[int, tuple[int, int]] = {}
    monkeypatch.setattr(curses, "start_color", lambda: None)
    monkeypatch.setattr(curses, "use_default_colors", lambda: None)
    monkeypatch.setattr(
        curses,
        "init_pair",
        lambda index, front, back: pairs.__setitem__(index, (front, back)),
    )
    monkeypatch.setattr(curses, "color_pair", lambda index: index * 256)
    screen = Screen([])
    scheme = start_colour(screen, {"background": "black"}, {"danger": "red"})
    assert screen.background is not None
    assert all(back == curses.COLOR_BLACK for _, back in pairs.values())
    assert scheme.tones["danger"]


def test_a_terminal_without_colour_still_draws() -> None:
    """Bold, dim and reverse say the same things where colour cannot."""
    screen = Screen([])
    draw(screen, choices(), 0, "", "Applications", scheme=Scheme())
    assert any("Alpha application" in line for line in screen.drawn)


def test_a_line_is_padded_so_its_colour_runs_the_width() -> None:
    """A highlight that stops after the text looks like a drawing fault."""
    screen = Screen([], width=40)
    draw(screen, choices(), 0, "", "Applications", scheme=Scheme())
    assert any(line.endswith(" " * 5) for line in screen.drawn)


def test_typing_builds_a_search_term() -> None:
    """The rule the chooser and the live view both follow, in one place."""
    from entrascope.picker import typed

    assert typed(ord("a"), "").term == "a"
    assert typed(ord("b"), "a").term == "ab"
    # Every change to the term sends the selection back to the top, because a
    # different term means a different list.
    assert typed(ord("b"), "a").reset is True


def test_backspace_shortens_the_term_and_never_underflows() -> None:
    """Backspacing an empty term is somebody pressing it once too often."""
    from entrascope.picker import BACKSPACE_KEYS, typed

    for key in BACKSPACE_KEYS:
        assert typed(key, "abc").term == "ab"
        assert typed(key, "").term == ""
        assert typed(key, "").searching is True


def test_escape_leaves_the_search_rather_than_adding_to_it() -> None:
    """A search with no way out but the interrupt key is a trap."""
    from entrascope.picker import typed

    outcome = typed(27, "payroll")
    assert outcome.term == ""
    assert outcome.searching is False


def test_a_second_slash_is_not_searched_for() -> None:
    """Somebody presses it twice because nothing told them the first one worked."""
    from entrascope.picker import typed

    assert typed(ord("/"), "").term == ""
    # Once there is a term, a slash is a character like any other: a redirect
    # URI is full of them and searching for one is a fair thing to want.
    assert typed(ord("/"), "https:").term == "https:/"


def test_a_key_that_is_not_a_character_leaves_the_term_alone() -> None:
    """A function key pressed mid search must not append anything."""
    import curses

    from entrascope.picker import typed

    outcome = typed(curses.KEY_F1, "payroll")
    assert outcome.term == "payroll"
    assert outcome.searching is True
    assert outcome.reset is False
