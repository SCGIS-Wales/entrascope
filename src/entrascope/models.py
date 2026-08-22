"""Immutable data transfer objects and the exception hierarchy.

Every object here is either a frozen NamedTuple or an exception type. There are
no service objects and no behaviour beyond construction.
"""

from __future__ import annotations

from typing import Literal, NamedTuple

#: The four authentication sources, in resolution order.
AuthSource = Literal["file", "env", "azure-cli", "default"]

AUTH_SOURCE_ORDER: tuple[AuthSource, ...] = ("file", "env", "azure-cli", "default")

#: Whether an identity carries application permissions or a user's own access.
IdentityKind = Literal["application", "delegated", "unknown"]


# framework contract: Python requires a class to define an exception type. These
# carry no behaviour beyond a message.
class EntrascopeError(Exception):
    """Base class for every error entrascope raises deliberately."""


# framework contract: Python requires a class to define an exception type.
class ConfigError(EntrascopeError):
    """Configuration is missing, malformed or fails its schema."""


# framework contract: Python requires a class to define an exception type.
class CredentialError(EntrascopeError):
    """Credentials are missing, malformed or unsafely stored."""


# framework contract: Python requires a class to define an exception type.
class AuthSourceUnavailableError(CredentialError):
    """The requested authentication source cannot be used on this machine."""


class Credential(NamedTuple):
    """Client credentials read from the credential file or the environment."""

    client_id: str
    tenant_id: str
    secret: str

    def __repr__(self) -> str:
        """Return a representation that cannot leak the secret."""
        return (
            f"Credential(client_id={self.client_id!r}, "
            f"tenant_id={self.tenant_id!r}, secret='[redacted]')"
        )


class AuthContext(NamedTuple):
    """The identity entrascope authenticated as, and how it did so."""

    source: AuthSource
    identity_kind: IdentityKind
    tenant_id: str | None
    client_id: str | None
    description: str


class CheckResult(NamedTuple):
    """The outcome of one preflight check."""

    check: str
    passed: bool
    detail: str
    remediation: str = ""
    docs_url: str = ""
