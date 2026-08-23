"""Live view tests, driven through a stub screen rather than a real terminal."""

from __future__ import annotations

import curses
import logging
from typing import Any

import pytest

from entrascope.config import Config
from entrascope.models import AuditEvent, SignInEvent
from entrascope.stream import (
    FLOORS,
    Row,
    columns,
    heading,
    line_of,
    matches,
    merge,
    read_events,
    row_from_audit,
    row_from_record,
    row_from_sign_in,
    rows_from,
    run,
    visible,
    wrapped,
)


# framework contract: curses passes a window object to the callback, so the
# double must answer the same handful of calls.
class Screen:
    """A screen that records what was drawn and replays scripted key presses."""

    def __init__(self, keys: list[int], height: int = 20, width: int = 120) -> None:
        self.keys = list(keys)
        self.size = (height, width)
        self.drawn: list[str] = []
        self.history: list[str] = []
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

    def timeout(self, milliseconds: int) -> None:
        self.tick = milliseconds

    def bkgd(self, character: str, attribute: int = 0) -> None:
        self.background = (character, attribute)

    def getch(self) -> int:
        # Running out of keys means the view did not do what the test expected.
        # Raising turns that into a failure rather than a wait for ever.
        if not self.keys:
            raise AssertionError(f"the view asked for another key: {self.drawn[:1]}")
        return self.keys.pop(0)


def sign_in(**overrides: Any) -> SignInEvent:
    """Return one sign in, failed unless a test says otherwise."""
    fields: dict[str, Any] = {
        "id": "1",
        "timestamp": "2026-08-23T09:15:00Z",
        "identity": "someone@example.invalid",
        "app_id": "6fb17f1c-7c19-41a5-bd50-63a16bd7346b",
        "app_display_name": "Payments API",
        "resource": "Microsoft Graph",
        "client_app": "Browser",
        "ip_address": "203.0.113.7",
        "error_code": 50011,
        "failure_reason": "The redirect URI does not match.",
    }
    return SignInEvent(**{**fields, **overrides})


def audit(**overrides: Any) -> AuditEvent:
    """Return one directory change, successful unless a test says otherwise."""
    fields: dict[str, Any] = {
        "id": "2",
        "activity": "Update application",
        "category": "ApplicationManagement",
        "result": "success",
        "reason": "",
        "timestamp": "2026-08-23T09:10:00Z",
        "initiated_by": "admin@example.invalid",
        "target": "Payments API",
        "target_id": "6fb17f1c-7c19-41a5-bd50-63a16bd7346b",
    }
    return AuditEvent(**{**fields, **overrides})


def record(level: int = logging.WARNING, message: str = "a call was refused") -> Any:
    """Return one log record, as the logging module would make it."""
    return logging.LogRecord("entrascope.http", level, "", 0, message, None, None)


def test_a_line_carries_the_identifier_beside_the_name(config: Config) -> None:
    """An error message quotes the identifier and never the display name."""
    row = row_from_sign_in(sign_in(), config)
    assert row.subject == "Payments API"
    assert row.about == "6fb17f1c-7c19-41a5-bd50-63a16bd7346b"
    assert row_from_sign_in(sign_in(app_display_name=""), config).subject == (
        "unnamed application"
    )


def test_a_failed_sign_in_is_an_error(config: Config) -> None:
    """Red is for what is already broken."""
    row = row_from_sign_in(sign_in(), config)
    assert row.severity == "error"
    assert "AADSTS50011" in row.detail
    assert row.subject == "Payments API"


def test_a_successful_sign_in_is_not(config: Config) -> None:
    """Colour that means something cannot be spent on everything."""
    row = row_from_sign_in(sign_in(error_code=0, failure_reason=""), config)
    assert row.severity == "ok"


def test_a_failed_directory_change_is_an_error(config: Config) -> None:
    """What counts as a failure is configuration, not a literal in the code."""
    assert row_from_audit(audit(result="failure"), config).severity == "error"
    assert row_from_audit(audit(), config).severity == "ok"


def test_the_timestamp_names_its_zone(config: Config) -> None:
    """A timestamp with no zone on it invites the wrong conclusion."""
    row = row_from_audit(audit(), config)
    assert row.when.startswith("2026-08-23 ")
    assert row.when.split()[-1].isalpha()


def test_a_log_record_becomes_a_line_like_any_other(config: Config) -> None:
    """The refusal that explains an empty screen belongs on the screen."""
    row = row_from_record(record(), config)
    assert row.severity == "warning"
    assert row.detail == "a call was refused"
    assert row.area == "entrascope"
    assert row.subject == "http"


def test_log_levels_map_onto_what_the_view_draws(config: Config) -> None:
    """Errors red, warnings amber, everything else quiet."""
    assert row_from_record(record(logging.ERROR), config).severity == "error"
    assert row_from_record(record(logging.INFO), config).severity == "note"


def test_nothing_is_shown_twice(config: Config) -> None:
    """Every poll asks for the newest events and most have been seen."""
    first = merge((), [row_from_audit(audit(), config)], 100)
    again = merge(first, [row_from_audit(audit(), config)], 100)
    assert len(again) == 1


def test_the_newest_line_is_at_the_top(config: Config) -> None:
    """Watching means reading downwards from now."""
    old = row_from_audit(
        audit(id="a", target_id="a", timestamp="2026-08-23T09:00:00Z"), config
    )
    new = row_from_audit(
        audit(id="b", target_id="b", timestamp="2026-08-23T09:30:00Z"), config
    )
    assert merge((), [old, new], 100)[0].keys == new.keys


def test_the_oldest_lines_fall_off(config: Config) -> None:
    """A view that keeps everything eventually keeps nothing else."""
    rows = [
        row_from_audit(
            audit(
                id=str(number),
                target_id=str(number),
                timestamp=f"2026-08-23T09:{number:02}:00Z",
            ),
            config,
        )
        for number in range(10)
    ]
    kept = merge((), rows, 3)
    assert len(kept) == 3
    assert kept[0].keys == frozenset({"audit:9"})


def test_a_filter_narrows_by_every_word(config: Config) -> None:
    """Two keywords mean both, which is what somebody typing two expects."""
    row = row_from_sign_in(sign_in(), config)
    assert matches(row, ["payments", "50011"])
    assert not matches(row, ["payments", "consent"])


def test_a_severity_floor_hides_what_is_below_it(config: Config) -> None:
    """A tenant is noisy, and most of the noise is not the problem."""
    rows = [
        row_from_sign_in(sign_in(), config),
        row_from_audit(audit(), config),
    ]
    assert len(visible(rows, "", FLOORS[0][1])) == 2
    assert len(visible(rows, "", FLOORS[2][1])) == 1


def test_the_columns_leave_the_detail_the_rest(config: Config) -> None:
    """The detail is the part that varies and the part being read."""
    rows = [row_from_sign_in(sign_in(), config)]
    widths = columns(rows, 120)
    line = line_of(rows[0], widths)
    assert line.index("AADSTS50011") > line.index("sign in")


def test_a_very_long_name_cannot_push_the_detail_off(config: Config) -> None:
    """One badly named application must not ruin every other line."""
    rows = [row_from_sign_in(sign_in(app_display_name="x" * 300), config)]
    when, _, subject, about, _ = columns(rows, 120)
    assert when + subject + about < 120


def test_an_identifier_is_never_the_part_that_is_cut(config: Config) -> None:
    """Half a GUID is no use to anybody."""
    rows = [row_from_sign_in(sign_in(app_display_name="x" * 300), config)]
    assert rows[0].about in line_of(rows[0], columns(rows, 120))


def test_the_heading_says_what_is_being_watched() -> None:
    """A screen that changes on its own has to say what it is doing."""
    assert "paused" in heading(10, 10, "", "everything", True, False)
    assert "watching" in heading(10, 10, "", "everything", False, False)
    assert "Filter" in heading(10, 2, "saml", "everything", False, True)


def test_a_detail_is_cut_into_a_fixed_number_of_lines() -> None:
    """The pane at the bottom is two lines, whatever the detail is."""
    assert wrapped("abcdef", 3, 2) == ("abc", "def")
    assert len(wrapped("x" * 500, 10, 2)) == 2
    assert wrapped("anything", 0, 2) == ()


def test_the_view_opens_on_what_is_already_known(config: Config) -> None:
    """An empty screen and a wait of one interval is a poor way to start."""
    from entrascope.models import Investigation

    result = Investigation(
        target="the whole tenant",
        scope="tenant",
        applications=(),
        service_principals=(),
        audit_events=(audit(),),
        sign_ins=(sign_in(),),
        findings=(),
        notes=(),
    )
    rows = rows_from(result, config)
    assert {row.area for row in rows} == {"directory", "sign in"}


def drive(
    monkeypatch: pytest.MonkeyPatch,
    config: Config,
    keys: list[int],
    rows: tuple[Row, ...] = (),
) -> Screen:
    """Run the view against a stub screen with scripted keys."""
    monkeypatch.setattr("entrascope.stream.read_events", lambda *a, **k: ())
    monkeypatch.setattr(curses, "start_color", lambda: None)
    monkeypatch.setattr(curses, "use_default_colors", lambda: None)
    monkeypatch.setattr(curses, "init_pair", lambda *a: None)
    monkeypatch.setattr(curses, "color_pair", lambda index: index)
    monkeypatch.setattr(curses, "curs_set", lambda value: 0)
    screen = Screen(keys)
    run(screen, config, None, (), "", rows)
    return screen


def test_q_returns_to_the_menu_rather_than_leaving(
    monkeypatch: pytest.MonkeyPatch, config: Config
) -> None:
    """Nothing in the live view exits the tool."""
    screen = drive(monkeypatch, config, [ord("q")])
    assert screen.keys == []


def test_escape_returns_too(monkeypatch: pytest.MonkeyPatch, config: Config) -> None:
    """Escape means go back, in every view that has one."""
    drive(monkeypatch, config, [27])


def test_a_filter_can_be_typed_and_cleared(
    monkeypatch: pytest.MonkeyPatch, config: Config
) -> None:
    """Typing narrows, escape clears it, and neither leaves the view."""
    rows = merge(
        (),
        [row_from_sign_in(sign_in(), config), row_from_audit(audit(), config)],
        100,
    )
    keys = [ord("/"), ord("p"), ord("a"), ord("y"), 27, ord("q")]
    screen = drive(monkeypatch, config, keys, rows)
    assert any("Filter: pay" in line for line in screen.history)


def test_moving_works_while_a_filter_is_being_typed(
    monkeypatch: pytest.MonkeyPatch, config: Config
) -> None:
    """Narrowing to two lines and then not being able to pick one is the bug."""
    rows = merge(
        (),
        [row_from_sign_in(sign_in(), config), row_from_audit(audit(), config)],
        100,
    )
    keys = [ord("/"), curses.KEY_DOWN, curses.KEY_UP, curses.KEY_NPAGE, 27, ord("q")]
    drive(monkeypatch, config, keys, rows)


def test_pausing_and_refreshing_say_so(
    monkeypatch: pytest.MonkeyPatch, config: Config
) -> None:
    """Somebody reading a line does not want it to scroll away underneath."""
    screen = drive(monkeypatch, config, [ord("p"), ord("r"), ord("f"), ord("q")])
    assert any("paused" in line for line in screen.history)
    assert any("errors only" in line or "warnings" in line for line in screen.history)


def test_a_tick_with_no_key_draws_again(
    monkeypatch: pytest.MonkeyPatch, config: Config
) -> None:
    """An event arriving must appear without anybody touching the keyboard."""
    drive(monkeypatch, config, [-1, -1, ord("q")])


def test_a_source_that_refuses_does_not_empty_the_view(
    monkeypatch: pytest.MonkeyPatch, config: Config
) -> None:
    """A tenant with no premium licence still has an audit log."""
    from entrascope.models import ApiCallError, ApiError

    def refuse(session: Any, config: Config, **kwargs: Any) -> Any:
        raise ApiCallError(
            ApiError(status=403, code="Denied", message="no", source="graph")
        )

    monkeypatch.setattr("entrascope.stream.query_audit_graph", refuse)
    monkeypatch.setattr("entrascope.stream.query_sign_ins_graph", refuse)
    assert read_events(config, None, kinds=("interactive",)) == ()


def test_the_same_failure_is_one_line_with_a_count(config: Config) -> None:
    """Forty lines saying the same thing is forty lines nobody reads."""
    rows = [
        row_from_sign_in(
            sign_in(id=str(number), timestamp=f"2026-08-23T09:{number:02}:00Z"), config
        )
        for number in range(5)
    ]
    merged = merge((), rows, 100)
    assert len(merged) == 1
    assert merged[0].occurrences() == 5


def test_a_counted_line_carries_the_most_recent_moment(config: Config) -> None:
    """The latest is the one worth reading, and the one worth timestamping."""
    old = row_from_sign_in(sign_in(id="a", timestamp="2026-08-23T09:00:00Z"), config)
    new = row_from_sign_in(
        sign_in(id="b", timestamp="2026-08-23T09:30:00Z", ip_address="198.51.100.9"),
        config,
    )
    merged = merge(merge((), [old], 100), [new], 100)
    assert merged[0].when == new.when
    assert "198.51.100.9" in merged[0].detail
    assert merged[0].occurrences() == 2


def test_the_same_event_arriving_twice_is_not_counted_twice(config: Config) -> None:
    """Every poll asks for the newest events, and most have been seen."""
    rows = merge((), [row_from_sign_in(sign_in(), config)], 100)
    again = merge(rows, [row_from_sign_in(sign_in(), config)], 100)
    assert again[0].occurrences() == 1


def test_a_repeated_refusal_is_said_once(config: Config) -> None:
    """Five kinds of sign in on a tenant with no licence is one problem."""
    rows = [record(message="no premium licence") for _ in range(4)]
    merged = merge((), [row_from_record(item, config) for item in rows], 100)
    assert len(merged) == 1
    assert merged[0].occurrences() == 4


def test_a_count_is_shown_only_when_there_is_one(config: Config) -> None:
    """A column of ones down the screen tells nobody anything."""
    from entrascope.stream import times

    single = row_from_audit(audit(), config)
    assert times(single) == ""
    assert times(single._replace(keys=frozenset({"a", "b"}))) == "x2"
