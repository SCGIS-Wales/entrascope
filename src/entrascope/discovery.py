"""Discovery of application registrations and enterprise applications.

Projection is a pure function of a Graph payload and the field mappings in
``config/fields.yaml``. Classification is a pure function of the projected
attributes and the classification values in the same file. Neither reaches the
network, so both are tested against fixtures alone.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from entrascope.config import Config
from entrascope.graph import fan_out_objects, get_collection
from entrascope.http import Session
from entrascope.logger import get_logger
from entrascope.models import (
    ApplicationSummary,
    ApplicationType,
    CredentialState,
    CredentialSummary,
    FederatedCredential,
    PermissionGrant,
    PermissionRequest,
    RedirectUris,
    SamlConfiguration,
    ServicePrincipalSummary,
)

log = get_logger(__name__)

#: Graph reports a delegated permission as Scope and an application permission
#: as Role inside requiredResourceAccess.
DELEGATED_MARKER = "Scope"
APPLICATION_MARKER = "Role"


def pluck(payload: Mapping[str, Any], path: str) -> Any:
    """Return a value from a payload by dotted path, or None if absent."""
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def strings(value: Any) -> tuple[str, ...]:
    """Coerce a Graph value into a tuple of strings."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(str(item) for item in value)
    return (str(value),)


def text(value: Any) -> str:
    """Coerce a Graph value into a string, treating absence as empty."""
    return "" if value is None else str(value)


def parse_timestamp(value: str) -> datetime | None:
    """Parse a Graph timestamp, tolerating the trailing Z and absent values."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def credential_state(
    end: datetime | None, warning_days: int, now: datetime
) -> tuple[CredentialState, int | None]:
    """Classify a credential by how long it has left."""
    if end is None:
        return "unknown", None
    remaining = (end - now).days
    if remaining < 0:
        return "expired", remaining
    if remaining <= warning_days:
        return "expiring", remaining
    return "valid", remaining


def project_credential(
    payload: Mapping[str, Any],
    config: Config,
    *,
    certificate: bool,
    now: datetime | None = None,
) -> CredentialSummary:
    """Project one password or key credential, with its expiry state."""
    mapping = config.fields.credential
    moment = now or datetime.now(UTC)
    end_text = text(pluck(payload, mapping["end"]))
    state, remaining = credential_state(
        parse_timestamp(end_text), config.fields.expiry.warning_days, moment
    )
    return CredentialSummary(
        key_id=text(pluck(payload, mapping["key_id"])),
        display_name=text(pluck(payload, mapping["display_name"])),
        kind="certificate" if certificate else "secret",
        start=text(pluck(payload, mapping["start"])),
        end=end_text,
        days_remaining=remaining,
        state=state,
    )


def project_credentials(
    payload: Mapping[str, Any],
    config: Config,
    mapping: Mapping[str, str],
    now: datetime | None = None,
) -> tuple[CredentialSummary, ...]:
    """Project every password and certificate credential on an object."""
    passwords = pluck(payload, mapping["password_credentials"]) or []
    keys = pluck(payload, mapping["key_credentials"]) or []
    return tuple(
        project_credential(item, config, certificate=is_certificate, now=now)
        for items, is_certificate in ((passwords, False), (keys, True))
        for item in items
        if isinstance(item, Mapping)
    )


def project_redirect_uris(payload: Mapping[str, Any], config: Config) -> RedirectUris:
    """Project the redirect URIs, keeping the platforms apart."""
    mapping = config.fields.application
    return RedirectUris(
        web=strings(pluck(payload, mapping["web_redirect_uris"])),
        single_page=strings(pluck(payload, mapping["spa_redirect_uris"])),
        public_client=strings(pluck(payload, mapping["public_client_redirect_uris"])),
    )


def project_requested_permissions(
    payload: Mapping[str, Any], config: Config
) -> tuple[PermissionRequest, ...]:
    """Project requiredResourceAccess into one entry per resource."""
    mapping = config.fields.application
    requested = pluck(payload, mapping["requested_permissions"]) or []
    results: list[PermissionRequest] = []
    for resource in requested:
        if not isinstance(resource, Mapping):
            continue
        access = resource.get("resourceAccess") or []
        delegated = tuple(
            text(item.get("id"))
            for item in access
            if isinstance(item, Mapping) and item.get("type") == DELEGATED_MARKER
        )
        application = tuple(
            text(item.get("id"))
            for item in access
            if isinstance(item, Mapping) and item.get("type") == APPLICATION_MARKER
        )
        results.append(
            PermissionRequest(
                resource_app_id=text(resource.get("resourceAppId")),
                delegated=delegated,
                application=application,
            )
        )
    return tuple(results)


def project_federated_credentials(
    payloads: Sequence[Mapping[str, Any]],
) -> tuple[FederatedCredential, ...]:
    """Project the workload identity federation credentials of an application."""
    return tuple(
        FederatedCredential(
            name=text(item.get("name")),
            issuer=text(item.get("issuer")),
            subject=text(item.get("subject")),
            audiences=strings(item.get("audiences")),
        )
        for item in payloads
        if isinstance(item, Mapping)
    )


def audience_label(sign_in_audience: str, config: Config) -> str:
    """Return a readable description of the sign in audience."""
    audiences = config.fields.classification.audiences
    labels = {
        audiences["single_tenant"]: "this tenant only",
        audiences["multi_tenant"]: "any tenant",
        audiences["multi_tenant_and_personal"]: "any tenant and personal accounts",
        audiences["personal_only"]: "personal accounts only",
    }
    return labels.get(sign_in_audience, "unrecognised audience")


def classify_application(
    redirect_uris: RedirectUris,
    credentials: Sequence[CredentialSummary],
    federated: Sequence[FederatedCredential],
) -> ApplicationType:
    """Classify an application registration from its projected attributes.

    The order matters. Federation is decisive because it changes how the
    application authenticates. A single page application is next, because its
    redirect URIs are registered on their own platform. A confidential client
    is one that holds a credential or registers a web redirect URI. What is
    left with only public client redirect URIs is a native or mobile client.
    """
    if federated:
        return "workload-identity-federation"
    if redirect_uris.single_page:
        return "single-page-application"
    if credentials or redirect_uris.web:
        return "confidential-client"
    if redirect_uris.public_client:
        return "native-or-mobile"
    return "public-client"


def classify_service_principal(
    payload: Mapping[str, Any], config: Config, tags: Sequence[str]
) -> ApplicationType:
    """Classify an enterprise application from its Graph payload."""
    rules = config.fields.classification
    mapping = config.fields.service_principal
    kind = text(pluck(payload, mapping["service_principal_type"]))
    if kind == rules.service_principal_types["managed_identity"]:
        return "managed-identity"
    if kind == rules.service_principal_types["legacy"]:
        return "legacy"
    mode = text(pluck(payload, mapping["preferred_single_sign_on_mode"]))
    if mode == rules.single_sign_on_modes["saml"]:
        gallery = any(tag in set(rules.gallery_tags) for tag in tags)
        return "saml-gallery" if gallery else "saml-non-gallery"
    if kind == rules.service_principal_types["application"]:
        return "confidential-client"
    return "unknown"


def project_application(
    payload: Mapping[str, Any],
    config: Config,
    *,
    owners: Sequence[Mapping[str, Any]] = (),
    federated: Sequence[Mapping[str, Any]] = (),
    now: datetime | None = None,
) -> ApplicationSummary:
    """Project one application registration into its immutable summary."""
    mapping = config.fields.application
    credentials = project_credentials(payload, config, mapping, now)
    redirect_uris = project_redirect_uris(payload, config)
    federated_credentials = project_federated_credentials(federated)
    audience = text(pluck(payload, mapping["sign_in_audience"]))
    version = pluck(payload, mapping["requested_access_token_version"])
    return ApplicationSummary(
        object_id=text(pluck(payload, mapping["object_id"])),
        app_id=text(pluck(payload, mapping["app_id"])),
        display_name=text(pluck(payload, mapping["display_name"])),
        application_type=classify_application(
            redirect_uris, credentials, federated_credentials
        ),
        sign_in_audience=audience,
        audience_label=audience_label(audience, config),
        redirect_uris=redirect_uris,
        identifier_uris=strings(pluck(payload, mapping["identifier_uris"])),
        requested_permissions=project_requested_permissions(payload, config),
        credentials=credentials,
        federated_credentials=federated_credentials,
        owners=owner_names(owners),
        requested_access_token_version=int(version)
        if isinstance(version, int)
        else None,
        created=text(pluck(payload, mapping["created"])),
    )


def owner_names(owners: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    """Return a readable name for each owner, whichever kind of object it is."""
    return tuple(
        text(item.get("displayName") or item.get("userPrincipalName") or item.get("id"))
        for item in owners
        if isinstance(item, Mapping)
    )


def project_saml(
    payload: Mapping[str, Any],
    config: Config,
    credentials: Sequence[CredentialSummary],
    tags: Sequence[str],
) -> SamlConfiguration | None:
    """Project the SAML configuration, or None when the application is not SAML."""
    rules = config.fields.classification
    mapping = config.fields.service_principal
    mode = text(pluck(payload, mapping["preferred_single_sign_on_mode"]))
    if mode != rules.single_sign_on_modes["saml"]:
        return None
    return SamlConfiguration(
        identifier_uris=strings(pluck(payload, mapping["identifier_uris"])),
        reply_urls=strings(pluck(payload, mapping["reply_urls"])),
        preferred_single_sign_on_mode=mode,
        signing_certificates=tuple(
            item for item in credentials if item.kind == "certificate"
        ),
        is_gallery=any(tag in set(rules.gallery_tags) for tag in tags),
    )


def project_granted_permissions(
    grants: Sequence[Mapping[str, Any]],
    assignments: Sequence[Mapping[str, Any]],
) -> tuple[PermissionGrant, ...]:
    """Project consent into the permissions actually granted.

    Delegated permissions come from the OAuth2 permission grants and are a
    space separated scope string. Application permissions come from the app
    role assignments.
    """
    delegated = tuple(
        PermissionGrant(
            resource_app_id=text(grant.get("resourceId")),
            kind="delegated",
            value=scope,
            principal=text(grant.get("principalId")) or "all users",
        )
        for grant in grants
        if isinstance(grant, Mapping)
        for scope in text(grant.get("scope")).split()
    )
    application = tuple(
        PermissionGrant(
            resource_app_id=text(assignment.get("resourceId")),
            kind="application",
            value=text(assignment.get("appRoleId")),
            principal=text(assignment.get("principalDisplayName")),
        )
        for assignment in assignments
        if isinstance(assignment, Mapping)
    )
    return delegated + application


def project_service_principal(
    payload: Mapping[str, Any],
    config: Config,
    *,
    owners: Sequence[Mapping[str, Any]] = (),
    grants: Sequence[Mapping[str, Any]] = (),
    assignments: Sequence[Mapping[str, Any]] = (),
    now: datetime | None = None,
) -> ServicePrincipalSummary:
    """Project one enterprise application into its immutable summary."""
    mapping = config.fields.service_principal
    tags = strings(pluck(payload, mapping["tags"]))
    credentials = project_credentials(payload, config, mapping, now)
    enabled = pluck(payload, mapping["account_enabled"])
    required = pluck(payload, mapping["app_role_assignment_required"])
    return ServicePrincipalSummary(
        object_id=text(pluck(payload, mapping["object_id"])),
        app_id=text(pluck(payload, mapping["app_id"])),
        display_name=text(pluck(payload, mapping["display_name"])),
        application_type=classify_service_principal(payload, config, tags),
        service_principal_type=text(pluck(payload, mapping["service_principal_type"])),
        sign_in_audience=text(pluck(payload, mapping["sign_in_audience"])),
        account_enabled=bool(enabled) if enabled is not None else True,
        app_role_assignment_required=bool(required),
        reply_urls=strings(pluck(payload, mapping["reply_urls"])),
        service_principal_names=strings(pluck(payload, mapping["identifier_uris"])),
        credentials=credentials,
        granted_permissions=project_granted_permissions(grants, assignments),
        saml=project_saml(payload, config, credentials, tags),
        owners=owner_names(owners),
        tags=tags,
        owner_tenant_id=text(pluck(payload, mapping["app_owner_organization_id"])),
    )


def is_first_party(principal: ServicePrincipalSummary, config: Config) -> bool:
    """Return whether an enterprise application belongs to Microsoft.

    A tenant carries hundreds of first party service principals. They are
    Microsoft's to manage, and reporting on them buries the findings that are
    actually yours.
    """
    owners = config.fields.classification.first_party_owner_tenants
    return principal.owner_tenant_id in owners


def discover_applications(
    session: Session,
    config: Config,
    token: Callable[[], str] | None = None,
    *,
    filter_expression: str | None = None,
    with_details: bool = True,
) -> tuple[ApplicationSummary, ...]:
    """Enumerate application registrations and project every one.

    Owners and federated identity credentials need one call per application, so
    they are fetched concurrently and only when details are wanted.
    """
    payloads = get_collection(
        session, config, "applications", filter_expression=filter_expression
    )
    object_ids = [text(item.get("id")) for item in payloads]
    owners: tuple[tuple[dict[str, Any], ...], ...] = ((),) * len(payloads)
    federated: tuple[tuple[dict[str, Any], ...], ...] = ((),) * len(payloads)
    if with_details and object_ids and token is not None:
        owners = fan_out_objects(object_ids, config, "application_owners", token)
        federated = fan_out_objects(
            object_ids, config, "federated_identity_credentials", token
        )
    log.info("discovered %s application registrations", len(payloads))
    return tuple(
        project_application(
            payload, config, owners=owner_rows, federated=federated_rows
        )
        for payload, owner_rows, federated_rows in zip(
            payloads, owners, federated, strict=True
        )
    )


def discover_service_principals(
    session: Session,
    config: Config,
    token: Callable[[], str] | None = None,
    *,
    filter_expression: str | None = None,
    with_details: bool = True,
) -> tuple[ServicePrincipalSummary, ...]:
    """Enumerate enterprise applications and project every one."""
    payloads = get_collection(
        session, config, "service_principals", filter_expression=filter_expression
    )
    object_ids = [text(item.get("id")) for item in payloads]
    owners: tuple[tuple[dict[str, Any], ...], ...] = ((),) * len(payloads)
    assignments: tuple[tuple[dict[str, Any], ...], ...] = ((),) * len(payloads)
    if with_details and object_ids and token is not None:
        owners = fan_out_objects(object_ids, config, "service_principal_owners", token)
        assignments = fan_out_objects(object_ids, config, "app_role_assignments", token)
    log.info("discovered %s enterprise applications", len(payloads))
    return tuple(
        project_service_principal(
            payload, config, owners=owner_rows, assignments=assignment_rows
        )
        for payload, owner_rows, assignment_rows in zip(
            payloads, owners, assignments, strict=True
        )
    )
