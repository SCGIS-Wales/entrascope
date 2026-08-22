"""The common logger.

Every module obtains its logger here. Nothing calls ``logging.getLogger``
directly and nothing calls ``print`` outside :mod:`entrascope.render`, both of
which a guard test enforces.

Three things are structural rather than remembered at each call site: secrets
are redacted by a filter before a record reaches a handler, a correlation id is
attached to every record, and the standard context fields name the
authentication source and the tenant, so that one failing tool call can be
traced through every Graph call it caused.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from contextvars import ContextVar
from pathlib import Path
from typing import Any, TextIO

from entrascope.config import Config, Logging
from entrascope.redaction import redact

#: The logger namespace. Every logger is a child of this one.
ROOT_NAME = "entrascope"

#: Record attributes that the formatters must not treat as context.
_STANDARD_ATTRIBUTES = frozenset(
    logging.LogRecord("", 0, "", 0, "", None, None).__dict__
)

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
_context: ContextVar[tuple[tuple[str, str], ...]] = ContextVar(
    "log_context", default=()
)


def new_correlation_id() -> str:
    """Generate and install a fresh correlation id, returning it."""
    value = uuid.uuid4().hex
    _correlation_id.set(value)
    return value


def set_correlation_id(value: str) -> None:
    """Install a correlation id supplied from outside, such as an HTTP header."""
    _correlation_id.set(value)


def get_correlation_id() -> str:
    """Return the correlation id in force, generating one if there is none."""
    current = _correlation_id.get()
    if not current:
        return new_correlation_id()
    return current


def bind_context(**fields: str) -> None:
    """Add standard context fields, such as the authentication source."""
    merged = dict(_context.get())
    merged.update({key: value for key, value in fields.items() if value})
    _context.set(tuple(sorted(merged.items())))


def get_context() -> dict[str, str]:
    """Return the context fields in force."""
    return dict(_context.get())


def clear_context() -> None:
    """Forget the correlation id and every context field."""
    _correlation_id.set("")
    _context.set(())


def record_context(record: logging.LogRecord) -> dict[str, Any]:
    """Return the extra fields carried by one record."""
    return {
        key: value
        for key, value in record.__dict__.items()
        if key not in _STANDARD_ATTRIBUTES and not key.startswith("_")
    }


# framework contract: the logging module requires a Filter subclass. The
# redaction logic itself lives in entrascope.redaction as free functions.
class _RedactionFilter(logging.Filter):
    """Redact every record, and attach the correlation id and context fields."""

    def __init__(self, settings: Logging) -> None:
        super().__init__()
        self._settings = settings

    def filter(self, record: logging.LogRecord) -> bool:
        redaction = self._settings.redaction
        record.msg = redact(record.msg, redaction)
        if record.args:
            record.args = redact(record.args, redaction)
        for key, value in record_context(record).items():
            setattr(record, key, redact(value, redaction))
        record.correlation_id = get_correlation_id()
        for key, value in get_context().items():
            if key in self._settings.context_fields:
                setattr(record, key, value)
        return True


def format_human(record: logging.LogRecord) -> str:
    """Render one record as a line for a person to read."""
    context = record_context(record)
    correlation = str(context.pop("correlation_id", ""))[:8]
    trailer = " ".join(f"{key}={value}" for key, value in sorted(context.items()))
    parts = [
        f"{record.levelname:<8}",
        f"[{correlation}]" if correlation else "",
        record.getMessage(),
        trailer,
    ]
    return " ".join(part for part in parts if part)


def format_json(record: logging.LogRecord) -> str:
    """Render one record as a JSON line."""
    payload: dict[str, Any] = {
        "timestamp": record.created,
        "level": record.levelname,
        "logger": record.name,
        "message": record.getMessage(),
    }
    payload.update(record_context(record))
    if record.exc_info is not None and record.exc_text:
        payload["exception"] = record.exc_text
    return json.dumps(payload, default=str, sort_keys=True)


# framework contract: the logging module requires a Formatter subclass. Both
# formatters delegate to the free functions above.
class _Formatter(logging.Formatter):
    """Delegate formatting to a free function chosen by configuration."""

    def __init__(self, style: str) -> None:
        super().__init__()
        self._render_style = style

    def format(self, record: logging.LogRecord) -> str:
        if record.exc_info is not None and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if self._render_style == "json":
            return format_json(record)
        return format_human(record)


def surface_settings(settings: Logging, surface: str) -> tuple[str, str]:
    """Return the format and destination in force for one surface."""
    override = settings.surfaces.get(surface)
    style = (
        override.format if override and override.format else None
    ) or settings.format
    destination = (
        override.destination if override and override.destination else None
    ) or settings.destination
    return style, destination


def open_destination(destination: str) -> TextIO:
    """Return the stream a destination names."""
    if destination == "stdout":
        return sys.stdout
    if destination == "stderr":
        return sys.stderr
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("a", encoding="utf-8")


def configure_logging(
    config: Config,
    surface: str = "cli",
    level: str | None = None,
) -> logging.Logger:
    """Install the handler, filter and formatter for one surface.

    Calling this again replaces the handlers rather than adding to them, so a
    repeated call in a test or in a long lived process cannot duplicate output.
    """
    settings = config.logging
    style, destination = surface_settings(settings, surface)
    logger = logging.getLogger(ROOT_NAME)
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
    handler = logging.StreamHandler(open_destination(destination))
    handler.setFormatter(_Formatter(style))
    # The filter is attached to the handler rather than to the logger. A filter
    # on a logger is not applied to records propagated from its children, and
    # every module logs through a child logger.
    handler.addFilter(_RedactionFilter(settings))
    logger.addHandler(handler)
    logger.setLevel((level or settings.level).upper())
    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return the logger for one module.

    Pass ``__name__``. The returned logger is a child of the entrascope logger,
    so it inherits the redaction filter, the correlation id and the configured
    handler.
    """
    if name == ROOT_NAME or name.startswith(f"{ROOT_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{ROOT_NAME}.{name}")
