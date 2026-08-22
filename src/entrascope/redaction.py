"""Secret redaction.

Redaction is structural rather than remembered. The functions here are applied
by the logging filter in :mod:`entrascope.logger`, so every record from every
module passes through them, and again by :mod:`entrascope.render` before
anything is written to a terminal or serialised.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from functools import lru_cache
from re import Pattern
from typing import Any

from entrascope.config import Config, Redaction, RedactionPattern

#: Maximum depth walked in a nested structure, to bound pathological input.
MAX_DEPTH = 12


@lru_cache(maxsize=32)
def compile_patterns(regexes: tuple[str, ...]) -> tuple[Pattern[str], ...]:
    """Compile the redaction patterns once."""
    return tuple(re.compile(regex) for regex in regexes)


def pattern_source(settings: Redaction) -> tuple[str, ...]:
    """Return the regular expressions configured for redaction."""
    return tuple(pattern.regex for pattern in settings.patterns)


def redact_text(text: str, settings: Redaction) -> str:
    """Replace every configured pattern found in a string."""
    result = text
    for pattern in compile_patterns(pattern_source(settings)):
        result = pattern.sub(settings.placeholder, result)
    return result


def is_secret_key(key: str, settings: Redaction) -> bool:
    """Return whether a mapping key names a value that must never be shown."""
    lowered = key.lower()
    return any(candidate.lower() == lowered for candidate in settings.keys)


def redact(value: Any, settings: Redaction, depth: int = 0) -> Any:
    """Return a copy of a value with every secret replaced.

    Mappings are walked by key, sequences by element, and strings by pattern.
    Anything else is returned unchanged, because a non string leaf cannot carry
    a token.
    """
    if depth >= MAX_DEPTH:
        return value
    if isinstance(value, str):
        return redact_text(value, settings)
    if isinstance(value, Mapping):
        return {
            key: (
                settings.placeholder
                if isinstance(key, str) and is_secret_key(key, settings)
                else redact(item, settings, depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(redact(item, settings, depth + 1) for item in value)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return [redact(item, settings, depth + 1) for item in value]
    return value


def redact_with_config(value: Any, config: Config) -> Any:
    """Redact a value using the redaction settings from configuration."""
    return redact(value, config.logging.redaction)


def register_secret(secret: str, settings: Redaction) -> Redaction:
    """Return redaction settings that also replace one literal secret.

    The credential loader calls this once the secret is known, so that a
    literal secret is caught even when it appears without a recognisable key or
    prefix.
    """
    if not secret:
        return settings
    escaped = re.escape(secret)
    existing = tuple(pattern.regex for pattern in settings.patterns)
    if escaped in existing:
        return settings
    addition = RedactionPattern(name="literal_secret", regex=escaped)
    return settings.model_copy(update={"patterns": (*settings.patterns, addition)})
