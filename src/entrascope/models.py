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


class ApiError(NamedTuple):
    """One failure from Microsoft Graph, Azure Monitor or the token endpoint."""

    status: int
    code: str
    message: str
    correlation_id: str = ""
    request_id: str = ""
    source: str = ""

    def summary(self) -> str:
        """Return a one line description of the failure.

        A status of zero means there was no reply at all, so saying that the
        service returned it would be nonsense.
        """
        source = self.source or "api"
        if self.status == 0:
            return f"could not reach {source}. {self.code}: {self.message}"
        return f"{source} returned {self.status} {self.code}: {self.message}"


# framework contract: Python requires a class to define an exception type.
class ApiCallError(EntrascopeError):
    """An API call failed. The structured detail is on the error attribute."""

    def __init__(self, error: ApiError) -> None:
        super().__init__(error.summary())
        self.error = error


class QueryResult(NamedTuple):
    """The result of one Azure Monitor log query."""

    columns: tuple[str, ...]
    rows: tuple[tuple[object, ...], ...]
    partial: bool = False
    detail: str = ""

    def as_dicts(self) -> tuple[dict[str, object], ...]:
        """Return the rows keyed by column name."""
        return tuple(dict(zip(self.columns, row, strict=False)) for row in self.rows)


#: How an application or enterprise application is classified.
ApplicationType = Literal[
    "confidential-client",
    "web-client",
    "api-or-resource",
    "enterprise-application",
    "public-client",
    "single-page-application",
    "native-or-mobile",
    "saml-gallery",
    "saml-non-gallery",
    "managed-identity",
    "workload-identity-federation",
    "legacy",
    "unknown",
]

#: The state of one credential relative to the configured warning window.
CredentialState = Literal["valid", "expiring", "expired", "unknown"]


class CredentialSummary(NamedTuple):
    """One password or certificate credential, with its expiry state."""

    key_id: str
    display_name: str
    kind: Literal["secret", "certificate"]
    start: str
    end: str
    days_remaining: int | None
    state: CredentialState


class RedirectUris(NamedTuple):
    """Redirect URIs, kept apart by platform because Entra treats them apart."""

    web: tuple[str, ...] = ()
    single_page: tuple[str, ...] = ()
    public_client: tuple[str, ...] = ()

    def total(self) -> int:
        """Return how many redirect URIs are registered across all platforms."""
        return len(self.web) + len(self.single_page) + len(self.public_client)


class PermissionRequest(NamedTuple):
    """Permissions requested against one resource, before consent."""

    resource_app_id: str
    delegated: tuple[str, ...] = ()
    application: tuple[str, ...] = ()


class PermissionGrant(NamedTuple):
    """A permission actually granted, which is what consent produces."""

    resource_app_id: str
    kind: Literal["delegated", "application"]
    value: str
    principal: str = ""


class FederatedCredential(NamedTuple):
    """One workload identity federation credential."""

    name: str
    issuer: str
    subject: str
    audiences: tuple[str, ...]


class SamlConfiguration(NamedTuple):
    """Single sign on configuration for a SAML enterprise application."""

    identifier_uris: tuple[str, ...]
    reply_urls: tuple[str, ...]
    preferred_single_sign_on_mode: str
    signing_certificates: tuple[CredentialSummary, ...]
    is_gallery: bool


class ApplicationSummary(NamedTuple):
    """One application registration, projected for diagnosis."""

    object_id: str
    app_id: str
    display_name: str
    application_type: ApplicationType
    sign_in_audience: str
    audience_label: str
    redirect_uris: RedirectUris
    identifier_uris: tuple[str, ...]
    requested_permissions: tuple[PermissionRequest, ...]
    credentials: tuple[CredentialSummary, ...]
    federated_credentials: tuple[FederatedCredential, ...]
    owners: tuple[str, ...]
    requested_access_token_version: int | None
    created: str
    exposes_api: bool = False

    def expiring(self) -> tuple[CredentialSummary, ...]:
        """Return the credentials that are expiring or already expired."""
        return tuple(
            item for item in self.credentials if item.state in ("expiring", "expired")
        )


class ServicePrincipalSummary(NamedTuple):
    """One enterprise application, projected for diagnosis."""

    object_id: str
    app_id: str
    display_name: str
    application_type: ApplicationType
    service_principal_type: str
    sign_in_audience: str
    account_enabled: bool
    app_role_assignment_required: bool
    reply_urls: tuple[str, ...]
    service_principal_names: tuple[str, ...]
    credentials: tuple[CredentialSummary, ...]
    granted_permissions: tuple[PermissionGrant, ...]
    saml: SamlConfiguration | None
    owners: tuple[str, ...]
    tags: tuple[str, ...]
    owner_tenant_id: str = ""

    def expiring(self) -> tuple[CredentialSummary, ...]:
        """Return the credentials that are expiring or already expired."""
        return tuple(
            item for item in self.credentials if item.state in ("expiring", "expired")
        )


class Explanation(NamedTuple):
    """What an error code means and what to do about it."""

    code: str
    meaning: str
    remediation: str
    docs_url: str
    likely_cause: str = ""
    known: bool = True


class AuditEvent(NamedTuple):
    """One directory audit event, from Graph or from Log Analytics."""

    id: str
    activity: str
    category: str
    result: str
    reason: str
    timestamp: str
    initiated_by: str
    target: str
    target_type: str = ""
    target_id: str = ""
    correlation_id: str = ""


class SignInEvent(NamedTuple):
    """One sign in, from Graph or from Log Analytics."""

    id: str
    timestamp: str
    identity: str
    app_id: str
    app_display_name: str
    resource: str
    client_app: str
    ip_address: str
    error_code: int
    failure_reason: str
    correlation_id: str = ""

    def failed(self) -> bool:
        """Return whether this sign in failed."""
        return self.error_code != 0


class GraphActivityEvent(NamedTuple):
    """One Microsoft Graph request made against the tenant."""

    timestamp: str
    app_id: str
    service_principal_id: str
    user_id: str
    method: str
    status: int
    uri: str
    roles: str
    scopes: str
    duration_ms: int
    request_id: str = ""


class NetworkTrust(NamedTuple):
    """The forward proxy and certificate trust in force for outbound calls."""

    trust_environment: bool
    verify: str
    verify_enabled: bool
    verify_source: str
    proxies: tuple[str, ...]

    def summary(self) -> str:
        """Return a one line description for the doctor report."""
        proxy = ", ".join(self.proxies) if self.proxies else "no proxy configured"
        trust = self.verify or self.verify_source
        return f"{proxy}; TLS verified against {trust}"


#: How serious a finding is. An error broke something, a warning will break
#: something, and a note is context that explains a result.
Severity = Literal["error", "warning", "note"]

SEVERITY_ORDER: tuple[Severity, ...] = ("error", "warning", "note")


class Finding(NamedTuple):
    """One thing worth an engineer's attention, with what to do about it."""

    severity: Severity
    area: str
    subject: str
    detail: str
    remediation: str = ""
    docs_url: str = ""
    occurrences: int = 1
    code: str = ""


class Investigation(NamedTuple):
    """Everything gathered about one application, or about the whole tenant."""

    target: str
    scope: Literal["application", "tenant"]
    applications: tuple[ApplicationSummary, ...]
    service_principals: tuple[ServicePrincipalSummary, ...]
    audit_events: tuple[AuditEvent, ...]
    sign_ins: tuple[SignInEvent, ...]
    findings: tuple[Finding, ...]
    notes: tuple[str, ...] = ()

    def errors(self) -> tuple[Finding, ...]:
        """Return only the findings that describe something already broken."""
        return tuple(item for item in self.findings if item.severity == "error")


class CheckResult(NamedTuple):
    """The outcome of one preflight check."""

    check: str
    passed: bool
    detail: str
    remediation: str = ""
    docs_url: str = ""
