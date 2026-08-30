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
from entrascope.graph import fan_out_objects, get_collection, odata_literal
from entrascope.http import Session
from entrascope.logger import get_logger
from entrascope.models import (
    ApiCallError,
    ApplicationSummary,
    ApplicationType,
    AppRoleAssignment,
    CredentialState,
    CredentialSummary,
    DirectoryMembership,
    FederatedCredential,
    PermissionGrant,
    PermissionRequest,
    RedirectUris,
    SamlConfiguration,
    ServicePrincipalSummary,
)

log = get_logger(__name__)


def pluck(payload: Mapping[str, Any], path: str) -> Any:
    """Return a value from a payload by dotted path, or None if absent.

    A key present verbatim wins over walking the path, because Microsoft Graph
    annotates a polymorphic collection with keys such as ``@odata.type`` that
    hold a dot and are not paths at all.
    """
    if path in payload:
        return payload[path]
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
    markers = config.fields.classification.resource_access_types
    requested = pluck(payload, mapping["requested_permissions"]) or []
    results: list[PermissionRequest] = []
    for resource in requested:
        if not isinstance(resource, Mapping):
            continue
        access = resource.get("resourceAccess") or []
        delegated = tuple(
            text(item.get("id"))
            for item in access
            if isinstance(item, Mapping) and item.get("type") == markers["delegated"]
        )
        application = tuple(
            text(item.get("id"))
            for item in access
            if isinstance(item, Mapping) and item.get("type") == markers["application"]
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
    exposes_api: bool = False,
) -> ApplicationType:
    """Classify an application registration from its projected attributes.

    The order matters. Federation is decisive because it changes how the
    application authenticates. A single page application is next, because its
    redirect URIs are registered on their own platform. An application that
    exposes an API and signs nobody in is a resource, not a client of any kind.
    A confidential client is one that holds a credential; a web application
    without one is a client all the same, and calling it confidential would say
    it holds a secret it does not have. What is left with only public client
    redirect URIs is a native or mobile client.
    """
    if federated:
        return "workload-identity-federation"
    if redirect_uris.single_page:
        return "single-page-application"
    if exposes_api and redirect_uris.total() == 0:
        return "api-or-resource"
    if credentials:
        return "confidential-client"
    if redirect_uris.web:
        return "web-client"
    if redirect_uris.public_client:
        return "native-or-mobile"
    return "public-client"


def selected_fields(mapping: Mapping[str, str]) -> tuple[str, ...]:
    """Return the Graph properties a projection needs, for $select.

    Asking for the whole object and using a tenth of it is the difference
    between a listing that answers and one that looks broken on a directory of
    several hundred. Only the first segment of a dotted path is a property.
    """
    return tuple(dict.fromkeys(path.split(".")[0] for path in mapping.values()))


def exposes_an_api(payload: Mapping[str, Any], config: Config) -> bool:
    """Return whether an application offers anything for others to call."""
    mapping = config.fields.application
    return bool(
        strings(pluck(payload, mapping["identifier_uris"]))
        or pluck(payload, mapping["app_roles"])
        or pluck(payload, mapping["oauth2_permission_scopes"])
    )


def classify_service_principal(
    payload: Mapping[str, Any], config: Config, tags: Sequence[str]
) -> ApplicationType:
    """Classify an enterprise application from its Graph payload.

    A service principal is the instance, not the definition. Whether the
    application behind it is confidential, public or a single page application
    is decided by its registration, which this object does not carry, so
    anything left after the kinds a service principal genuinely determines is
    named for what it is rather than guessed at.
    """
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
        return "enterprise-application"
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
    exposes = exposes_an_api(payload, config)
    return ApplicationSummary(
        object_id=text(pluck(payload, mapping["object_id"])),
        app_id=text(pluck(payload, mapping["app_id"])),
        display_name=text(pluck(payload, mapping["display_name"])),
        application_type=classify_application(
            redirect_uris, credentials, federated_credentials, exposes
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
        exposes_api=exposes,
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
    config: Config,
) -> tuple[PermissionGrant, ...]:
    """Project consent into the permissions actually granted.

    Delegated permissions come from the OAuth2 permission grants, where the
    scope is a space separated string and the consent type says whether an
    administrator recorded it for the tenant or one person recorded it for
    themselves. Application permissions come from the app role assignments the
    enterprise application holds against a resource, and there is no such thing
    as one of those without admin consent.
    """
    grant_fields = config.fields.oauth2_permission_grant
    role_fields = config.fields.app_role_assignment
    tenant_wide = config.fields.classification.consent_types["tenant_wide"]
    delegated = tuple(
        PermissionGrant(
            resource_app_id=text(pluck(grant, grant_fields["resource_id"])),
            kind="delegated",
            value=scope,
            principal=(text(pluck(grant, grant_fields["principal_id"])) or "all users"),
            consent_type=text(pluck(grant, grant_fields["consent_type"])),
            principal_id=text(pluck(grant, grant_fields["principal_id"])),
            admin_consent_recorded=(
                text(pluck(grant, grant_fields["consent_type"])) == tenant_wide
            ),
        )
        for grant in grants
        if isinstance(grant, Mapping)
        for scope in text(pluck(grant, grant_fields["scope"])).split()
    )
    application = tuple(
        PermissionGrant(
            resource_app_id=text(assignment.get("resourceId")),
            kind="application",
            value=text(pluck(assignment, role_fields["app_role_id"])),
            principal=text(pluck(assignment, role_fields["principal_display_name"])),
            resource_display_name=text(
                pluck(assignment, role_fields["resource_display_name"])
            ),
            # An application permission cannot be granted any other way, so
            # holding one is itself the record that an administrator consented.
            admin_consent_required=True,
            admin_consent_recorded=True,
        )
        for assignment in assignments
        if isinstance(assignment, Mapping)
    )
    return delegated + application


def project_app_role_assignments(
    payloads: Sequence[Mapping[str, Any]], config: Config
) -> tuple[AppRoleAssignment, ...]:
    """Project who has been assigned to an enterprise application.

    A principal here is a person, a security group or another application. The
    null app role identifier means the assignment carries access and no role,
    which is what assigning a group to an application without roles produces,
    so it is said in words rather than left as a row of zeroes.
    """
    mapping = config.fields.app_role_assignment
    rules = config.fields.classification
    empty = rules.default_access_app_role_id
    return tuple(
        AppRoleAssignment(
            principal_id=text(pluck(item, mapping["principal_id"])),
            principal_display_name=text(pluck(item, mapping["principal_display_name"])),
            principal_type=text(pluck(item, mapping["principal_type"])),
            app_role_id=text(pluck(item, mapping["app_role_id"])),
            meaning=(
                "access to the application, carrying no role"
                if text(pluck(item, mapping["app_role_id"])) in ("", empty)
                else "an application role"
            ),
            resource_display_name=text(pluck(item, mapping["resource_display_name"])),
            created=text(pluck(item, mapping["created"])),
        )
        for item in payloads
        if isinstance(item, Mapping)
    )


def named_app_role_assignments(
    assignments: Sequence[AppRoleAssignment], names: Mapping[str, str]
) -> tuple[AppRoleAssignment, ...]:
    """Fill in the name of each assigned role, where the resource defines one."""
    return tuple(
        item._replace(app_role_value=names.get(item.app_role_id, ""))
        for item in assignments
    )


def project_memberships(
    payloads: Sequence[Mapping[str, Any]], config: Config
) -> tuple[DirectoryMembership, ...]:
    """Project the groups, roles and units an object belongs to.

    A memberOf collection is polymorphic, so what each row is comes from its
    OData type. A row of an unrecognised type is kept and named by its type
    rather than dropped, because silently losing a membership is worse than
    showing one this tool has no word for.
    """
    mapping = config.fields.membership
    kinds = {
        odata_type: name
        for name, odata_type in config.fields.classification.membership_types.items()
    }
    return tuple(
        project_membership(item, mapping, kinds)
        for item in payloads
        if isinstance(item, Mapping)
    )


def project_membership(
    item: Mapping[str, Any], mapping: Mapping[str, str], kinds: Mapping[str, str]
) -> DirectoryMembership:
    """Project one row of a memberOf collection."""
    odata_type = text(pluck(item, mapping["odata_type"]))
    return DirectoryMembership(
        object_id=text(pluck(item, mapping["object_id"])),
        display_name=text(pluck(item, mapping["display_name"])),
        kind=kinds.get(odata_type, odata_type or "unknown"),
        security_enabled=boolean(pluck(item, mapping["security_enabled"])),
        mail_enabled=boolean(pluck(item, mapping["mail_enabled"])),
        membership_rule=text(pluck(item, mapping["membership_rule"])),
        on_premises_sync_enabled=boolean(
            pluck(item, mapping["on_premises_sync_enabled"])
        ),
        description=text(pluck(item, mapping["description"])),
    )


def boolean(value: Any) -> bool | None:
    """Return a Graph flag, keeping absence apart from false.

    A group that is not security enabled and a group whose flag was not read
    are different answers, and reporting both as false would say the first
    where the second is true.
    """
    return None if value is None else bool(value)


def security_groups(
    memberships: Sequence[DirectoryMembership], config: Config
) -> tuple[DirectoryMembership, ...]:
    """Return only the security groups out of a set of memberships.

    A distribution list carries no access. Filtering to the groups that do is
    what makes the answer to "what can this reach through a group" readable. A
    group whose flag was not read is kept, because leaving out a group that may
    carry access is the worse of the two mistakes.
    """
    wanted = config.fields.classification.access_bearing_membership
    return tuple(
        item
        for item in memberships
        if item.kind == wanted and item.security_enabled is not False
    )


def memberships_of_kind(
    memberships: Sequence[DirectoryMembership], kind: str
) -> tuple[DirectoryMembership, ...]:
    """Return the memberships of one kind."""
    return tuple(item for item in memberships if item.kind == kind)


def project_service_principal(
    payload: Mapping[str, Any],
    config: Config,
    *,
    owners: Sequence[Mapping[str, Any]] = (),
    grants: Sequence[Mapping[str, Any]] = (),
    assignments: Sequence[Mapping[str, Any]] = (),
    assigned_to: Sequence[Mapping[str, Any]] = (),
    member_of: Sequence[Mapping[str, Any]] = (),
    now: datetime | None = None,
) -> ServicePrincipalSummary:
    """Project one enterprise application into its immutable summary.

    The two kinds of app role assignment are different things and are read from
    different endpoints. ``assignments`` are the application permissions this
    application holds against other resources, from appRoleAssignments.
    ``assigned_to`` are the people and groups allowed to use this application,
    from appRoleAssignedTo. Conflating them is the mistake this signature
    exists to make hard.
    """
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
        granted_permissions=project_granted_permissions(grants, assignments, config),
        saml=project_saml(payload, config, credentials, tags),
        owners=owner_names(owners),
        tags=tags,
        created=text(pluck(payload, mapping["created"])),
        owner_tenant_id=text(pluck(payload, mapping["app_owner_organization_id"])),
        assignments=project_app_role_assignments(assigned_to, config),
        member_of=project_memberships(member_of, config),
    )


def is_first_party(principal: ServicePrincipalSummary, config: Config) -> bool:
    """Return whether an enterprise application belongs to Microsoft.

    A tenant carries hundreds of first party service principals. They are
    Microsoft's to manage, and reporting on them buries the findings that are
    actually yours.
    """
    owners = config.fields.classification.first_party_owner_tenants
    return principal.owner_tenant_id in owners


def expansion(config: Config, endpoint: str) -> str:
    """Return what a collection expands, if configuration says it expands one."""
    return config.endpoints.graph.expansions.get(endpoint, "")


def expanded(
    payloads: Sequence[Mapping[str, Any]], name: str
) -> tuple[tuple[dict[str, Any], ...], ...]:
    """Return one expanded collection per object, in the order they came."""
    return tuple(
        tuple(item for item in payload.get(name, ()) if isinstance(item, dict))
        for payload in payloads
    )


def discover_applications(
    session: Session,
    config: Config,
    token: Callable[[], str] | None = None,
    *,
    filter_expression: str | None = None,
    with_details: bool = True,
    with_federated: bool = True,
    limit: int | None = None,
) -> tuple[ApplicationSummary, ...]:
    """Enumerate application registrations and project every one.

    Owners come back with the page, expanded, because one call per application
    is thousands of calls on a real tenant. Federated identity credentials
    cannot be expanded, so they are fetched concurrently and only when they are
    wanted.
    """
    payloads = get_collection(
        session,
        config,
        "applications",
        select=selected_fields(config.fields.application),
        filter_expression=filter_expression,
        limit=limit,
        expand=expansion(config, "applications") if with_details else "",
    )
    object_ids = [text(item.get("id")) for item in payloads]
    owners = expanded(payloads, "owners")
    federated: tuple[tuple[dict[str, Any], ...], ...] = ((),) * len(payloads)
    if with_details and with_federated and object_ids and token is not None:
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


def delegated_grants_by_client(
    session: Session, config: Config
) -> dict[str, tuple[dict[str, Any], ...]]:
    """Read every delegated permission grant in the tenant, keyed by client.

    One paged call answers this for the whole directory. Asking per application
    would be a call each, and consent is the thing most often missing, so it is
    read for every application rather than only for the one being looked at.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    field = config.fields.oauth2_permission_grant["client_id"]
    for row in get_collection(session, config, "oauth2_permission_grants"):
        grouped.setdefault(text(pluck(row, field)), []).append(row)
    return {key: tuple(value) for key, value in grouped.items()}


def grants_for_client(
    session: Session, config: Config, object_id: str
) -> tuple[dict[str, Any], ...]:
    """Read the delegated permission grants of one enterprise application.

    Filtered at Graph rather than read whole and sifted here, because a tenant
    holds a grant for every application anybody has ever consented to.
    """
    if not object_id:
        return ()
    field = config.fields.oauth2_permission_grant["client_id"]
    return get_collection(
        session,
        config,
        "oauth2_permission_grants",
        filter_expression=f"{field} eq '{odata_literal(object_id)}'",
    )


def discover_service_principals(
    session: Session,
    config: Config,
    token: Callable[[], str] | None = None,
    *,
    filter_expression: str | None = None,
    with_details: bool = True,
    with_assignments: bool = True,
    with_consent: bool = True,
    limit: int | None = None,
) -> tuple[ServicePrincipalSummary, ...]:
    """Enumerate enterprise applications and project every one.

    Application permissions are read from appRoleAssignments, which is what the
    application holds. Delegated consent is read once for the whole tenant and
    matched up here, because that is one call rather than one per application.
    """
    payloads = get_collection(
        session,
        config,
        "service_principals",
        select=selected_fields(config.fields.service_principal),
        filter_expression=filter_expression,
        limit=limit,
        expand=expansion(config, "service_principals") if with_details else "",
    )
    object_ids = [text(item.get("id")) for item in payloads]
    owners = expanded(payloads, "owners")
    assignments: tuple[tuple[dict[str, Any], ...], ...] = ((),) * len(payloads)
    if with_details and with_assignments and object_ids and token is not None:
        assignments = fan_out_objects(object_ids, config, "granted_app_roles", token)
    grants: dict[str, tuple[dict[str, Any], ...]] = {}
    # Consent is read whether or not the per object details are wanted, because
    # it is one paged call for the whole tenant rather than a call each, and it
    # is the thing most often missing.
    if with_consent and object_ids:
        try:
            grants = delegated_grants_by_client(session, config)
        except ApiCallError as error:
            # Consent is worth having and is not worth failing a listing for.
            log.warning("could not read delegated consent: %s", error.error.summary())
    log.info("discovered %s enterprise applications", len(payloads))
    return tuple(
        project_service_principal(
            payload,
            config,
            owners=owner_rows,
            grants=grants.get(object_id, ()),
            assignments=assignment_rows,
        )
        for payload, object_id, owner_rows, assignment_rows in zip(
            payloads, object_ids, owners, assignments, strict=True
        )
    )
