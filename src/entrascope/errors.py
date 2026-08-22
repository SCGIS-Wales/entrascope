"""Error code interpretation.

One mapping, read from ``config/error-codes.yaml``, is the only place an AADSTS
or Microsoft Graph code is interpreted. An unrecognised code returns the
configured default rather than nothing, because a code with no entry still needs
a link and a next step.
"""

from __future__ import annotations

import re

from entrascope.config import Config, ErrorEntry
from entrascope.logger import get_logger
from entrascope.models import ApiError, Explanation

log = get_logger(__name__)

#: AADSTS codes appear inside a longer message, so they are extracted by pattern.
AADSTS_PATTERN = re.compile(r"\bAADSTS\d{3,8}\b")


def find_aadsts(text: str) -> str:
    """Return the first AADSTS code in a message, or an empty string."""
    found = AADSTS_PATTERN.search(text or "")
    return found.group(0) if found else ""


def normalise(code: str) -> str:
    """Return a code in the form the configuration file uses."""
    return (code or "").strip()


def lookup(code: str, config: Config) -> ErrorEntry | None:
    """Return the configured entry for one code, matching case insensitively."""
    entries = config.error_codes.errors
    exact = entries.get(code)
    if exact is not None:
        return exact
    lowered = code.lower()
    for name, entry in entries.items():
        if name.lower() == lowered:
            return entry
    return None


def explain(code: str, config: Config) -> Explanation:
    """Explain one error code, falling back to the configured default.

    The code may arrive on its own or embedded in a longer message, which is how
    AADSTS codes reach us from the token endpoint.
    """
    candidate = normalise(code)
    entry = lookup(candidate, config)
    if entry is None:
        embedded = find_aadsts(candidate)
        if embedded:
            candidate, entry = embedded, lookup(embedded, config)
    if entry is None:
        default = config.error_codes.defaults
        log.debug("no configured explanation for %s", candidate)
        return Explanation(
            code=candidate,
            meaning=default.meaning,
            remediation=default.remediation,
            docs_url=default.docs_url,
            likely_cause=default.likely_cause or "",
            known=False,
        )
    return Explanation(
        code=candidate,
        meaning=entry.meaning,
        remediation=entry.remediation,
        docs_url=entry.docs_url,
        likely_cause=entry.likely_cause or "",
    )


def explain_api_error(error: ApiError, config: Config) -> Explanation:
    """Explain a failed API call, preferring an AADSTS code in the message.

    The token endpoint reports a generic code such as invalid_client alongside a
    specific AADSTS code in the description, and the specific one is the useful
    one.
    """
    embedded = find_aadsts(error.message)
    if embedded:
        return explain(embedded, config)
    return explain(error.code, config)


def known_codes(config: Config) -> tuple[str, ...]:
    """Return every code the configuration explains, in order."""
    return tuple(sorted(config.error_codes.errors))


def search(term: str, config: Config) -> tuple[Explanation, ...]:
    """Return every explanation whose code or meaning mentions a term."""
    lowered = term.lower()
    return tuple(
        explain(code, config)
        for code, entry in config.error_codes.errors.items()
        if lowered in code.lower() or lowered in entry.meaning.lower()
    )
