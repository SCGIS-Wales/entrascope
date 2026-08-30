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
    #: What was tried on the way and why it was passed over. A source that was
    #: expected to work and quietly did not is the commonest confusion there
    #: is, so the answer carries the reasons with it.
    skipped: tuple[str, ...] = ()


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
    """A permission actually granted, which is what consent produces.

    The consent type is the part that decides whether a permission works for
    everybody or for one person. A delegated permission consented tenant wide
    needed an administrator; the same permission consented by one person for
    themselves works for them and is refused for everybody else.
    """

    resource_app_id: str
    kind: Literal["delegated", "application"]
    value: str
    principal: str = ""
    #: AllPrincipals or Principal for a delegated grant, empty for an
    #: application permission, which is always tenant wide.
    consent_type: str = ""
    #: The object id of the person a single user grant belongs to, where there
    #: is one. Empty on a tenant wide grant, which belongs to nobody.
    principal_id: str = ""
    resource_display_name: str = ""
    #: Whether only an administrator may consent to this permission. None when
    #: the resource could not be read to find out.
    admin_consent_required: bool | None = None
    #: Whether consent for it was in fact recorded by an administrator.
    admin_consent_recorded: bool = False


class AppRoleAssignment(NamedTuple):
    """One principal granted access to an enterprise application.

    This is the other half of authorisation and the half that is usually
    missing: a user, a security group or another application assigned to the
    enterprise application. Where assignment is required, an identity that is
    not here cannot sign in whatever has been consented.
    """

    principal_id: str
    principal_display_name: str
    #: User, Group or ServicePrincipal, as Microsoft Graph reports it.
    principal_type: str
    app_role_id: str
    #: The name of the role, where the enterprise application defines one.
    #: Empty when the assignment carries only access and no role.
    app_role_value: str = ""
    #: Said in words, because the null identifier means access and not a role.
    meaning: str = ""
    resource_display_name: str = ""
    created: str = ""


class DirectoryMembership(NamedTuple):
    """One group, directory role or administrative unit an object belongs to.

    A security group is the one that carries access. Whether a group is
    security enabled, and whether its membership is a rule rather than a list,
    both change what adding somebody to it actually does.
    """

    object_id: str
    display_name: str
    #: group, directory role or administrative unit.
    kind: str
    security_enabled: bool | None = None
    mail_enabled: bool | None = None
    #: The rule of a dynamic group. Empty when membership is assigned.
    membership_rule: str = ""
    on_premises_sync_enabled: bool | None = None
    description: str = ""


class FederatedCredential(NamedTuple):
    """One workload identity federation credential."""

    name: str
    issuer: str
    subject: str
    audiences: tuple[str, ...]


class SamlConfiguration(NamedTuple):
    """Single sign on configuration for a SAML enterprise application.

    The identifier and the reply URL are compared byte for byte by the service
    provider, and the signing certificate is what the assertion is trusted by,
    so all three are the first things to check when a SAML integration stops
    working. Which certificate signs is decided by a thumbprint rather than by
    which is newest, and nobody is warned of an expiry unless an address is
    registered to warn.
    """

    identifier_uris: tuple[str, ...]
    reply_urls: tuple[str, ...]
    preferred_single_sign_on_mode: str
    signing_certificates: tuple[CredentialSummary, ...]
    is_gallery: bool
    #: Names the certificate that actually signs. With more than one on the
    #: object this is the only thing that says which.
    preferred_signing_key_thumbprint: str = ""
    #: Where Entra warns that the signing certificate is about to expire. Empty
    #: is why a SAML integration stops working with no warning at all.
    notification_email_addresses: tuple[str, ...] = ()
    #: Where the service provider sends somebody to begin sign in, which is
    #: what makes an identity provider initiated flow work.
    login_url: str = ""
    logout_url: str = ""
    #: The key issued assertions are encrypted with, where the service provider
    #: requires encryption.
    token_encryption_key_id: str = ""
    relay_state: str = ""


class PreAuthorizedApplication(NamedTuple):
    """A client allowed to ask for this resource's scopes without a prompt.

    This is what makes an on behalf of chain work without the person consenting
    to the middle tier separately. A client absent here, or present without the
    scope it asks for, produces a consent prompt in a flow that has no user
    present to answer one.
    """

    app_id: str
    #: The scopes this client may ask for, named where the resource could be
    #: read to name them.
    permissions: tuple[str, ...] = ()
    display_name: str = ""


class AssignedPolicy(NamedTuple):
    """One policy assigned to an enterprise application.

    A claims mapping policy changes what a token carries, a home realm
    discovery policy changes where the person is sent to authenticate, and a
    token lifetime policy changes how long the result is good for. None of it
    is recorded on the application, so a registration compared against a token
    it produced explains none of the difference.
    """

    object_id: str
    display_name: str
    kind: str
    definition: tuple[str, ...] = ()
    is_organization_default: bool | None = None


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
    #: Whether Entra treats this as a public client when a token request does
    #: not say which it is. A confidential client with this true is refused
    #: when it presents a secret; a native one with it false is refused when it
    #: does not.
    is_fallback_public_client: bool = False
    #: Whether the application accepts claims a policy mapped. A claims mapping
    #: policy assigned without this is ignored rather than refused.
    accepts_mapped_claims: bool = False
    #: The clients allowed to ask for this resource's scopes without a consent
    #: prompt, which is what makes an on behalf of chain work.
    pre_authorized_applications: tuple[PreAuthorizedApplication, ...] = ()

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
    created: str = ""
    owner_tenant_id: str = ""
    #: Who may use this enterprise application: the users, security groups and
    #: applications assigned to it.
    assignments: tuple[AppRoleAssignment, ...] = ()
    #: The groups, directory roles and administrative units this application's
    #: own identity belongs to.
    member_of: tuple[DirectoryMembership, ...] = ()
    #: The claims mapping, home realm discovery and token lifetime policies
    #: assigned to it, each of which changes a token without the registration
    #: recording that it does.
    policies: tuple[AssignedPolicy, ...] = ()

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
    #: The application id or object id of the subject, where it has one. An
    #: error message quotes the identifier and never the display name, and two
    #: applications in a tenant may share a name.
    identifier: str = ""
    #: When the evidence for this was recorded, where there is a moment to
    #: name. Configuration has no timestamp; a failed sign in does.
    when: str = ""
    detail: str = ""
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
