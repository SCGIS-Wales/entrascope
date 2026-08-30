"""A live view of what a tenant is doing.

An investigation is a photograph. Watching a sign in fail while somebody is on
the telephone describing it is a different job, and a report that prints once
and returns to the shell cannot do it.

This follows the audit log and the sign in logs, newest at the top, and shows
the tool's own log lines in the same list rather than letting them scribble
over the screen. Errors are red, warnings amber, everything else quiet. Type to
narrow by keyword. Nothing here exits the tool: leaving returns to the menu
that opened it.
"""

from __future__ import annotations

import curses
import logging
import time
from collections import deque
from collections.abc import Callable, Iterator, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:  # pragma: no cover
    from curses import window
else:  # pragma: no cover
    window = object

from entrascope.config import Config
from entrascope.http import Session, build_session, refusal_reported_by_caller
from entrascope.logger import get_logger, handed_to
from entrascope.logs import (
    query_audit_graph,
    query_sign_ins_graph,
    sign_in_kinds,
)
from entrascope.models import ApiCallError, AuditEvent, SignInEvent
from entrascope.picker import (
    DOWN_KEYS,
    PAGE,
    QUIT_KEYS,
    SEARCH_KEYS,
    UP_KEYS,
    Scheme,
    hide_cursor,
    start_colour,
    typed,
)
from entrascope.redaction import redact_with_config
from entrascope.render import flatten, format_timestamp

log = get_logger(__name__)

#: How the log levels map onto the meanings the view draws.
LEVELS: dict[str, str] = {
    "CRITICAL": "error",
    "ERROR": "error",
    "WARNING": "warning",
    "INFO": "note",
    "DEBUG": "note",
}

#: Severity floors, cycled with f. Each shows itself and everything worse.
FLOORS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("everything", ("error", "warning", "note", "ok")),
    ("warnings and worse", ("error", "warning")),
    ("errors only", ("error",)),
)


#: How long the view waits for a key before drawing again. Short enough that
#: an arriving event appears at once, long enough not to spin.
TICK_MS = 250

HELP_LINE = (
    "  / filter, f severity, p pause, r refresh now, up and down to move, "
    "q back to the menu"
)
SEARCH_LINE = "  type to narrow, enter keeps it, escape clears it"


class Row(NamedTuple):
    """One line in the live view.

    The keys are the events this line stands for. Every poll asks for the
    newest events and most of what comes back has been shown already, so an
    event seen once stays seen; and the same failure happening forty times is
    one line saying forty rather than forty lines saying the same thing.

    The signature is what makes two lines the same thing: the same code against
    the same application, or the same refusal from the tool. What differs
    between them, the address it came from and the moment, is taken from the
    most recent, which is the one worth reading.

    The subject and what it is about are separate because an error message
    quotes the identifier and never the display name, and two applications in a
    tenant may share a name. Kept apart, the identifier is never the part that
    gets truncated to fit.
    """

    signature: str
    keys: frozenset[str]
    when: str
    severity: str
    area: str
    subject: str
    about: str
    detail: str

    def occurrences(self) -> int:
        """Return how many times this line has happened.

        Not named count, because a tuple already has one of those and shadowing
        it would be a trap for anybody who reached for the usual meaning.
        """
        return len(self.keys)

    def text(self) -> str:
        """Return everything a keyword could match on this line."""
        return (
            f"{self.when} {self.severity} {self.area} {self.subject} "
            f"{self.about} {self.detail}"
        )


def row_from_sign_in(event: SignInEvent, config: Config) -> Row:
    """Return the line for one sign in."""
    detail = (
        f"{event.identity or 'unknown identity'} from "
        f"{event.ip_address or 'an unrecorded address'}"
    )
    if event.failed():
        detail = (
            f"AADSTS{event.error_code}: {event.failure_reason or 'no reason recorded'}"
            f". {detail}"
        )
    return Row(
        # The same code against the same application is the same problem,
        # however many people it happens to.
        signature=f"signin:{event.app_id}:{event.error_code}",
        keys=frozenset({f"signin:{event.id}"}),
        when=format_timestamp(event.timestamp, config),
        severity="error" if event.failed() else "ok",
        area="sign in",
        # A display name is somebody else's text and a line here is one line.
        # A newline would forge a row and an escape sequence would move the
        # cursor about, so neither reaches the screen.
        subject=flatten(event.app_display_name) or "unnamed application",
        about=flatten(event.app_id),
        detail=flatten(detail),
    )


def row_from_audit(event: AuditEvent, config: Config) -> Row:
    """Return the line for one directory change."""
    result = event.result.lower()
    failures = config.fields.findings.audit_failure_results
    severity = "error" if result in failures else "ok"
    detail = f"{event.activity} by {event.initiated_by or 'an unnamed caller'}"
    if event.reason:
        detail = f"{detail}. {event.reason}"
    return Row(
        signature=f"audit:{event.activity}:{event.target_id}:{event.result}",
        keys=frozenset({f"audit:{event.id}"}),
        when=format_timestamp(event.timestamp, config),
        severity=severity,
        area="directory",
        subject=flatten(event.target or event.activity),
        about=flatten(event.target_id),
        detail=flatten(detail),
    )


def row_from_record(record: logging.LogRecord, config: Config) -> Row:
    """Return the line for one of the tool's own log records.

    The tool's own lines belong in the same list as the tenant's events. They
    are what says a call was refused, and hiding them while a full screen view
    owns the terminal would leave somebody watching an empty screen with no
    idea why. The moment is written the same way an event's is, so the two
    sort against each other and read as one list.
    """
    moment = datetime.fromtimestamp(record.created, tz=UTC).isoformat()
    return Row(
        signature=f"log:{record.name}:{record.levelname}:{record.getMessage()}",
        keys=frozenset({f"log:{record.created}:{record.relativeCreated}"}),
        when=format_timestamp(moment, config),
        severity=LEVELS.get(record.levelname, "note"),
        area="entrascope",
        subject=record.name.removeprefix("entrascope."),
        about="",
        # Redacted again here rather than relied upon. The filter that redacts
        # is attached to the handler this view displaces, and a secret reaching
        # a screen because of how the screen was being drawn would be an
        # indefensible way to leak one.
        detail=flatten(str(redact_with_config(record.getMessage(), config))),
    )


def read_events(
    config: Config,
    token: Callable[[], str] | None,
    *,
    kinds: Sequence[str],
    app_id: str = "",
) -> tuple[Row, ...]:
    """Read the newest events from every source, tolerating a refusal.

    One source refusing must not empty the view. A tenant without a premium
    licence cannot read sign ins at all and its audit log still answers.
    """
    settings = config.fields.display.stream
    limit = settings.poll_events
    rows: list[Row] = []
    refusals: list[tuple[str, str]] = []
    # A shorter wait than a report gets. The view asks again in a moment
    # anyway, and a call still hanging when somebody leaves the view would keep
    # the process alive after it while nothing was on the screen.
    quick = config.model_copy(
        update={
            "retry": config.retry.model_copy(
                update={
                    "http": config.retry.http.model_copy(
                        update={
                            "connect_timeout_seconds": settings.timeout_seconds,
                            "read_timeout_seconds": settings.timeout_seconds,
                        }
                    )
                }
            )
        }
    )

    def read(session: Session, source: str) -> tuple[Row, ...]:
        # The shorter timeouts are read from the configuration handed to the
        # call rather than from the session, so the call gets them too.
        if source == "audit":
            events = query_audit_graph(session, quick, top=limit)
            return tuple(row_from_audit(event, config) for event in events)
        sign_ins = query_sign_ins_graph(
            session, quick, kind=source, app_id=app_id or None, top=limit
        )
        return tuple(row_from_sign_in(event, config) for event in sign_ins)

    session = build_session(quick, token)
    try:
        # One line per reason, said here with the sources named, rather than
        # one from the transport and one from here for every source of every
        # poll. A tenant missing one permission refuses every source for the
        # same reason, and five identical lines say nothing one does not.
        with refusal_reported_by_caller():
            for source in ("audit", *kinds):
                try:
                    rows.extend(read(session, source))
                except ApiCallError as failure:
                    refusals.append((source, failure.error.summary()))
    finally:
        session.close()
    for note in collapse(refusals):
        log.warning("%s", note)
    return tuple(rows)


def collapse(refusals: Sequence[tuple[str, str]]) -> tuple[str, ...]:
    """Turn one refusal per source into one line per reason."""
    by_reason: dict[str, list[str]] = {}
    for source, reason in refusals:
        by_reason.setdefault(reason, []).append(source)
    return tuple(
        f"Unavailable for {', '.join(sorted(sources))}: {reason}"
        for reason, sources in by_reason.items()
    )


def drain(arriving: deque[Row]) -> tuple[Row, ...]:
    """Take everything waiting, one item at a time so nothing is dropped."""
    taken: list[Row] = []
    while True:
        try:
            taken.append(arriving.popleft())
        except IndexError:
            return tuple(taken)


def combine(older: Row, newer: Row) -> Row:
    """Return one line standing for both, at the more recent moment.

    Which of the two is more recent is decided by the timestamp rather than by
    the order they arrived in, because a poll returns a page of events at once
    and the audit log is not always written in order.
    """
    latest = newer if newer.when >= older.when else older
    return latest._replace(keys=older.keys | newer.keys)


def merge(
    existing: Sequence[Row], arriving: Sequence[Row], maximum: int
) -> tuple[Row, ...]:
    """Return the lines to show, newest first, each said once.

    Ordering is by the timestamp as it reads, which sorts correctly because it
    is written largest unit first.
    """
    seen = {key for row in existing for key in row.keys}
    folded = {row.signature: row for row in existing}
    for row in arriving:
        if row.keys & seen:
            continue
        seen |= row.keys
        current = folded.get(row.signature)
        folded[row.signature] = combine(current, row) if current else row
    ordered = sorted(folded.values(), key=lambda row: row.when, reverse=True)
    return tuple(ordered[:maximum])


def matches(row: Row, terms: Sequence[str]) -> bool:
    """Return whether a line matches every keyword typed."""
    text = row.text().lower()
    return all(term in text for term in terms)


def visible(rows: Sequence[Row], term: str, allowed: Sequence[str]) -> list[Row]:
    """Return the lines a filter and a severity floor leave showing.

    Drawing happens several times a second, so an empty filter does no work
    rather than building the text of two thousand lines to match nothing
    against.
    """
    terms = term.lower().split()
    if not terms:
        return [row for row in rows if row.severity in allowed]
    return [row for row in rows if row.severity in allowed and matches(row, terms)]


def columns(rows: Sequence[Row], width: int) -> tuple[int, int, int, int, int]:
    """Return the width of every column but the detail.

    The identifier is given whatever it needs, because half of one is no use to
    anybody. The name is what gets cut when the screen is narrow, and the
    detail takes what is left, being the part that varies and the part somebody
    is reading.
    """
    when = max((len(row.when) for row in rows), default=19)
    area = max((len(row.area) for row in rows), default=9)
    about = max((len(row.about) for row in rows), default=0)
    counted = max((len(times(row)) for row in rows), default=0)
    wanted = max((len(row.subject) for row in rows), default=20)
    # Ten for the gaps between the columns. What is left after the identifier
    # is what the name may have, because a name cut short is still a name and
    # half an identifier is nothing at all. On a screen too narrow for both,
    # the name shrinks to a stub rather than the identifier disappearing.
    spare = width - (when + counted + area + about + 10)
    return when, area, max(8, min(wanted, spare)), about, counted


def times(row: Row) -> str:
    """Return how many times a line has happened, or nothing if it is one."""
    return f"x{row.occurrences()}" if row.occurrences() > 1 else ""


def line_of(row: Row, widths: tuple[int, int, int, int, int]) -> str:
    """Return one line, in columns."""
    when, area, subject, about, counted = widths
    return (
        f"  {row.when:<{when}}  {times(row):>{counted}}  {row.area:<{area}}  "
        f"{row.subject[:subject]:<{subject}}  {row.about:<{about}}  {row.detail}"
    )


def heading(
    total: int, showing: int, term: str, floor: str, paused: bool, searching: bool
) -> str:
    """Return the line along the top, which says what is being watched."""
    if searching:
        return f"Filter: {term}▏    {showing} of {total} lines match"
    state = "paused" if paused else "watching"
    narrowed = f", matching {term!r}" if term else ""
    return f"Live, {state}  ({showing} of {total} lines, {floor}{narrowed})"


def draw(
    screen: window,
    rows: Sequence[Row],
    selected: int,
    scheme: Scheme,
    *,
    total: int,
    term: str,
    floor: str,
    paused: bool,
    searching: bool,
) -> None:
    """Draw the view once, newest at the top."""
    screen.erase()
    height, width = screen.getmaxyx()
    # Two lines at the top for the heading, three at the bottom for the detail
    # of the selected line and the help.
    body = max(1, height - 6)
    top = max(0, min(selected - body // 2, max(0, len(rows) - body)))
    screen.addnstr(
        0,
        0,
        heading(total, len(rows), term, floor, paused, searching).ljust(width - 1),
        width - 1,
        scheme.heading,
    )
    widths = columns(rows, width)
    for offset, row in enumerate(rows[top : top + body]):
        index = top + offset
        style = (
            scheme.highlight
            if index == selected
            else scheme.tones.get(row.severity, scheme.normal)
        )
        screen.addnstr(
            offset + 2, 0, line_of(row, widths).ljust(width - 1), width - 1, style
        )
    if rows:
        chosen = rows[min(selected, len(rows) - 1)]
        # A detail is often a sentence and a half. The line above is truncated
        # so the columns stay readable, and the whole of it goes here.
        for number, part in enumerate(wrapped(chosen.detail, width - 4, 2)):
            screen.addnstr(height - 3 + number, 2, part, width - 3, scheme.normal)
    footer = SEARCH_LINE if searching else HELP_LINE
    screen.addnstr(height - 1, 0, footer.ljust(width - 1), width - 1, scheme.hint)
    screen.refresh()


def wrapped(text: str, width: int, lines: int) -> tuple[str, ...]:
    """Return a string cut into a fixed number of lines."""
    if width < 1:
        return ()
    pieces = [text[start : start + width] for start in range(0, len(text), width)]
    return tuple(pieces[:lines])


def poller(
    config: Config,
    token: Callable[[], str] | None,
    *,
    kinds: Sequence[str],
    app_id: str,
) -> Callable[[], tuple[Row, ...]]:
    """Return the function one poll runs, with everything it needs bound."""

    def poll() -> tuple[Row, ...]:
        return read_events(config, token, kinds=kinds, app_id=app_id)

    return poll


def run(
    screen: window,
    config: Config,
    token: Callable[[], str] | None,
    kinds: Sequence[str],
    app_id: str,
    initial: Sequence[Row],
) -> None:
    """Drive the live view until it is left.

    Polling happens on one worker so that the view stays responsive while a
    call is in flight, and the worker holds its own session, which is the
    thread safety boundary requests documents.
    """
    settings = config.fields.display.stream
    palette = config.fields.display.chooser
    scheme = start_colour(
        screen,
        {
            "background": palette.background,
            "foreground": palette.foreground,
            "highlight": palette.highlight,
            "heading": palette.heading,
            "hint": palette.hint,
        },
        {
            severity: colour
            for severity, colour in settings.severity_tones.items()
            if colour
        },
    )
    hide_cursor()
    screen.timeout(TICK_MS)
    poll = poller(config, token, kinds=kinds, app_id=app_id)

    rows = merge((), initial, settings.maximum_rows)
    # A log record can arrive on the polling thread while the drawing thread is
    # emptying this. Reading a list and then clearing it is two steps, and a
    # record that lands between them is lost; taking from one end of a deque is
    # one step, and losing the line that says why the screen is empty would be
    # the worst line to lose.
    arriving: deque[Row] = deque(maxlen=settings.maximum_rows)
    term = ""
    searching = False
    paused = False
    selected = 0
    floor = 0
    due = 0.0
    pending: Future[tuple[Row, ...]] | None = None

    pool = ThreadPoolExecutor(max_workers=1)
    try:

        def take(record: logging.LogRecord, written: str) -> None:
            _ = written
            arriving.append(row_from_record(record, config))

        with handed_to(take):
            while True:
                taken = drain(arriving)
                if taken:
                    rows = merge(rows, taken, settings.maximum_rows)
                if pending is not None and pending.done():
                    rows = merge(rows, harvest(pending), settings.maximum_rows)
                    pending = None
                    due = time.monotonic() + settings.interval_seconds
                if pending is None and not paused and time.monotonic() >= due:
                    pending = pool.submit(poll)

                shown = visible(rows, term, FLOORS[floor][1])
                selected = max(0, min(selected, len(shown) - 1)) if shown else 0
                draw(
                    screen,
                    shown,
                    selected,
                    scheme,
                    total=len(rows),
                    term=term,
                    floor=FLOORS[floor][0],
                    paused=paused,
                    searching=searching,
                )

                key = screen.getch()
                if key == -1:
                    continue
                if (key in DOWN_KEYS and not searching) or key == curses.KEY_DOWN:
                    selected += 1
                    continue
                if (key in UP_KEYS and not searching) or key == curses.KEY_UP:
                    selected = max(0, selected - 1)
                    continue
                if key == curses.KEY_NPAGE:
                    selected += PAGE
                    continue
                if key == curses.KEY_PPAGE:
                    selected = max(0, selected - PAGE)
                    continue
                if key in (10, 13, curses.KEY_ENTER):
                    searching = False
                    continue
                if searching:
                    outcome = typed(key, term)
                    term, searching = outcome.term, outcome.searching
                    if outcome.reset:
                        selected = 0
                    continue
                if key in QUIT_KEYS:
                    return
                if key in SEARCH_KEYS:
                    searching, term = True, ""
                    continue
                if key == ord("p"):
                    paused = not paused
                    continue
                if key == ord("r"):
                    due = 0.0
                    continue
                if key == ord("f"):
                    floor = (floor + 1) % len(FLOORS)
                    selected = 0
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def harvest(pending: Future[tuple[Row, ...]]) -> tuple[Row, ...]:
    """Return what a finished poll read, or nothing if it failed.

    A poll that fails must not end the view. The failure was logged where it
    happened, and that log line arrives in the view like any other.
    """
    try:
        return pending.result()
    except ApiCallError as error:
        log.warning("poll failed: %s", error.error.summary())
    except Exception as error:
        log.warning("poll failed: %s", error)
    return ()


def rows_from(investigation: Any, config: Config) -> tuple[Row, ...]:
    """Return the lines for what an investigation already read.

    The view opens on what is known rather than on an empty screen and a wait
    of one polling interval.
    """
    rows = [row_from_audit(event, config) for event in investigation.audit_events]
    rows.extend(row_from_sign_in(event, config) for event in investigation.sign_ins)
    return tuple(rows)


def follow(
    config: Config,
    token: Callable[[], str] | None,
    *,
    kinds: Sequence[str] | None = None,
    app_id: str = "",
    initial: Sequence[Row] = (),
) -> None:
    """Open the live view, and return to the caller when it is left."""
    skipped = config.fields.display.stream.skip_kinds
    wanted = (
        tuple(kinds)
        if kinds
        else tuple(kind for kind in sign_in_kinds(config) if kind not in skipped)
    )
    try:
        # framework contract: curses takes over the terminal through a wrapper
        # that restores it afterwards, whatever happens.
        curses.wrapper(run, config, token, wanted, app_id, initial)
    except curses.error as error:  # pragma: no cover
        log.warning("could not draw the live view: %s", error)


def events_of(rows: Sequence[Row]) -> Iterator[Mapping[str, str]]:
    """Return the lines as plain records, for a pipe or a file."""
    for row in rows:
        yield {
            "when": row.when,
            "severity": row.severity,
            "area": row.area,
            "subject": row.subject,
            "detail": row.detail,
        }
