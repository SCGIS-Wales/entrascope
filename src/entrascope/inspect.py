"""Everything about one application, in one place.

Discovery lists. This inspects: one application registration and its enterprise
application together, with the scopes it exposes, the roles it defines, what it
has asked for, what has actually been consented, every URL it is registered
with, its credentials and their expiry, and its single sign on configuration.

The projection is ordered for reading rather than alphabetically, because the
first question is always what this is, and the last is usually where to click.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any, NamedTuple

from entrascope.config import Config
from entrascope.discovery import (
    classify_application,
    discover_applications,
    discover_service_principals,
    grants_for_client,
    memberships_of_kind,
    named_app_role_assignments,
    owner_names,
    pluck,
    project_application,
    project_federated_credentials,
    project_policies,
    project_pre_authorized,
    project_service_principal,
    security_groups,
    strings,
    text,
)
from entrascope.graph import get_collection, get_object, odata_literal
from entrascope.http import Session
from entrascope.logger import get_logger
from entrascope.models import (
    ApiCallError,
    ApplicationSummary,
    AssignedPolicy,
    PermissionGrant,
    ServicePrincipalSummary,
)
from entrascope.picker import Choice, Tone
from entrascope.render import flatten, portal_link, to_payload

log = get_logger(__name__)


class Catalogue(NamedTuple):
    """Everything inspectable, read once.

    Discovery is the expensive part, and offering a chooser and then inspecting
    what was chosen used to walk the directory twice.
    """

    applications: tuple[ApplicationSummary, ...]
    principals: tuple[ServicePrincipalSummary, ...]
    #: What was kept out of the list, and why. Hiding things silently is worse
    #: than showing too many.
    hidden: tuple[str, ...] = ()

    def lines(self) -> tuple[Choice, ...]:
        """Return the chooser lines, coloured by what each one means."""
        seen = {item.app_id for item in self.applications}
        named: list[tuple[str, str, str, Tone, str]] = [
            (
                item.app_id or item.object_id,
                item.display_name,
                "",
                tone_for_application(item),
                item.created,
            )
            for item in self.applications
        ]
        named.extend(
            (
                item.app_id or item.object_id,
                item.display_name,
                "enterprise",
                tone_for_principal(item),
                item.created,
            )
            for item in self.principals
            if item.app_id not in seen
        )
        width = min(
            max((len(name) for _, name, _, _, _ in named), default=0), NAME_WIDTH
        )
        rows = tuple(
            Choice(
                key=key,
                label=f"{shorten(name, width):<{width}}  {key}"
                + (f"  [{marker}]" if marker else ""),
                tone=tone,
                created=created,
                name=name,
            )
            for key, name, marker, tone, created in named
        )
        return tuple(sorted(rows, key=lambda line: line.name.lower()))


#: The widest a name is allowed to be before the identifier column. Long
#: enough for almost every display name, short enough that the identifiers are
#: still on the screen.
NAME_WIDTH = 56


def tone_for_application(item: ApplicationSummary) -> Tone:
    """Return what an application registration should look like in the list.

    An expired secret is the thing somebody is most often hunting for, so it is
    the one that shouts. One about to expire warns. Everything else is an
    ordinary OAuth application.
    """
    states = {credential.state for credential in item.credentials}
    if "expired" in states:
        return "danger"
    if "expiring" in states:
        return "warning"
    return "oauth"


def tone_for_principal(item: ServicePrincipalSummary) -> Tone:
    """Return what an enterprise application should look like in the list.

    A managed identity is checked first, because Azure rotates its credentials
    on its own schedule and an expired one there is not somebody's problem to
    fix. Anywhere else an expired credential is the loudest thing on the line.
    """
    if item.application_type in ("managed-identity", "legacy"):
        return "quiet"
    states = {credential.state for credential in item.credentials}
    if "expired" in states:
        return "danger"
    if "expiring" in states:
        return "warning"
    if item.saml is not None or item.application_type.startswith("saml"):
        return "saml"
    return "oauth"


def shorten(name: str, width: int) -> str:
    """Return a name that fits, with an ellipsis where it was cut.

    A display name is somebody else's text and the chooser draws it on a
    screen, so a newline or an escape sequence is taken out before anything is
    measured or cut.
    """
    plain = flatten(name)
    return plain if len(plain) <= width else plain[: width - 1] + "\u2026"


def chooser_fields(config: Config, collection: str) -> tuple[str, ...]:
    """Return the Graph properties the chooser reads for one collection.

    Which properties those are is configuration, like every other field
    mapping, so a site that wants another column in the list adds it there
    rather than here.
    """
    return tuple(config.fields.chooser_select.get(collection, ()))


def read_catalogue(
    session: Session,
    config: Config,
    token: Callable[[], str] | None = None,
    *,
    everything: bool = False,
) -> Catalogue:
    """Read enough of every application to offer a list of them.

    Names and identifiers only. Everything else is read for the one
    application that is chosen, because reading it for all of them means a
    call per object and a directory of several hundred then takes minutes.
    """
    from entrascope.discovery import is_first_party

    applications = tuple(
        project_application(payload, config)
        for payload in get_collection(
            session,
            config,
            "applications",
            select=chooser_fields(config, "applications"),
        )
    )
    principals = tuple(
        project_service_principal(payload, config)
        for payload in get_collection(
            session,
            config,
            "service_principals",
            select=chooser_fields(config, "service_principals"),
        )
    )
    hidden: list[str] = []
    if not everything:
        before = len(principals)
        principals = tuple(
            item for item in principals if not is_first_party(item, config)
        )
        if before != len(principals):
            hidden.append(
                f"{before - len(principals)} Microsoft first party enterprise "
                "applications"
            )
        kinds = set(config.fields.classification.hidden_from_the_chooser)
        before = len(principals)
        principals = tuple(
            item for item in principals if item.application_type not in kinds
        )
        if before != len(principals):
            hidden.append(
                f"{before - len(principals)} of type {', '.join(sorted(kinds))}"
            )
    log.info(
        "read %s application registrations and %s enterprise applications",
        len(applications),
        len(principals),
    )
    return Catalogue(
        applications=applications, principals=principals, hidden=tuple(hidden)
    )


def candidates(
    session: Session,
    config: Config,
    token: Callable[[], str] | None = None,
    *,
    include_first_party: bool = False,
) -> tuple[tuple[str, str], ...]:
    """Return every application that can be inspected, as identifier and label."""
    from entrascope.discovery import is_first_party

    applications = discover_applications(session, config, token, with_details=False)
    principals = discover_service_principals(session, config, token, with_details=False)
    if not include_first_party:
        principals = tuple(
            item for item in principals if not is_first_party(item, config)
        )
    seen = {item.app_id for item in applications}
    rows = [
        (item.app_id or item.object_id, f"{item.display_name}  ({item.app_id})")
        for item in applications
    ]
    rows.extend(
        (
            item.app_id or item.object_id,
            f"{item.display_name}  ({item.app_id})  [enterprise]",
        )
        for item in principals
        if item.app_id not in seen
    )
    return tuple(sorted(rows, key=lambda pair: pair[1].lower()))


def matching(
    summaries: Sequence[Any], term: str, kinds: Sequence[str] = ()
) -> tuple[Any, ...]:
    """Return the summaries matching a term and, optionally, a type.

    A term may be a display name or part of one, an application id or an object
    id, because an engineer has whichever the error message gave them.
    """
    lowered = term.lower()
    found = tuple(
        item
        for item in summaries
        if not term
        or lowered in item.display_name.lower()
        or lowered == item.app_id.lower()
        or lowered == item.object_id.lower()
    )
    if kinds:
        wanted = {kind.lower() for kind in kinds}
        found = tuple(item for item in found if item.application_type in wanted)
    return found


class PermissionFact(NamedTuple):
    """What one permission identifier or scope name actually is.

    Resolved from the resource that defines it, because a registration records
    only an identifier and nobody can read one of those.
    """

    value: str
    kind: str
    #: Whether only an administrator may consent to it. An application
    #: permission always needs one; a delegated scope needs one when the
    #: resource says so.
    admin_consent_required: bool
    resource: str = ""


class PermissionCatalogue(NamedTuple):
    """Every permission the resources define, keyed both ways.

    A requested permission is recorded as an identifier and a delegated grant
    is recorded as a scope name, so both have to be resolvable.
    """

    by_id: dict[str, PermissionFact]
    by_value: dict[tuple[str, str], PermissionFact]
    resource_names: dict[str, str]
    #: Resources that could not be read. A report full of unresolved
    #: identifiers should say why rather than look like the answer.
    unresolved: tuple[str, ...] = ()

    def fact_for_id(self, identifier: str) -> PermissionFact | None:
        """Return what a permission identifier means, if it was resolved."""
        return self.by_id.get(identifier)

    def fact_for_value(self, resource: str, value: str) -> PermissionFact | None:
        """Return what a scope name means against one resource."""
        return self.by_value.get((resource, value))


def read_permission_catalogue(
    session: Session,
    config: Config,
    *,
    app_ids: Sequence[str] = (),
    object_ids: Sequence[str] = (),
) -> PermissionCatalogue:
    """Read the permissions each named resource defines.

    A requested permission carries the resource application id and a granted
    one carries the resource object id, so a resource is looked up by whichever
    of the two is to hand and then recorded under both.
    """
    scope_type = config.fields.classification.admin_consent_scope_type
    by_id: dict[str, PermissionFact] = {}
    by_value: dict[tuple[str, str], PermissionFact] = {}
    resource_names: dict[str, str] = {}
    unresolved: list[str] = []
    wanted = [("app_id", value) for value in dict.fromkeys(app_ids) if value]
    wanted += [("object_id", value) for value in dict.fromkeys(object_ids) if value]
    for kind, identifier in wanted:
        if identifier in resource_names:
            continue
        rows = _read_resource(session, config, kind, identifier)
        if rows is None:
            unresolved.append(identifier)
            continue
        for row in rows:
            keys = [
                text(row.get("id")),
                text(row.get("appId")),
                identifier,
            ]
            name = text(row.get("displayName"))
            for key in keys:
                if key:
                    resource_names[key] = name
            for scope in row.get("oauth2PermissionScopes") or []:
                if not isinstance(scope, Mapping):
                    continue
                fact = PermissionFact(
                    value=text(scope.get("value")),
                    kind="delegated",
                    admin_consent_required=text(scope.get("type")) == scope_type,
                    resource=name,
                )
                if scope.get("id"):
                    by_id[text(scope["id"])] = fact
                for key in keys:
                    if key and fact.value:
                        by_value[(key, fact.value)] = fact
            for role in row.get("appRoles") or []:
                if not isinstance(role, Mapping):
                    continue
                fact = PermissionFact(
                    value=text(role.get("value")) or text(role.get("displayName")),
                    kind="application",
                    # An application permission is never self consented.
                    admin_consent_required=True,
                    resource=name,
                )
                if role.get("id"):
                    by_id[text(role["id"])] = fact
                for key in keys:
                    if key and fact.value:
                        by_value[(key, fact.value)] = fact
    return PermissionCatalogue(
        by_id=by_id,
        by_value=by_value,
        resource_names=resource_names,
        unresolved=tuple(unresolved),
    )


def _read_resource(
    session: Session, config: Config, kind: str, identifier: str
) -> tuple[dict[str, Any], ...] | None:
    """Read one resource enterprise application, or None when it is refused."""
    endpoint = (
        "service_principal_by_app_id" if kind == "app_id" else "service_principal_by_id"
    )
    try:
        if kind == "app_id":
            return get_collection(
                session,
                config,
                endpoint,
                path_parameters={"app_id": identifier},
            )
        return (
            get_object(
                session,
                config,
                endpoint,
                path_parameters={"object_id": identifier},
            ),
        )
    except ApiCallError as error:
        log.debug("could not resolve %s: %s", identifier, error.error.summary())
        return None


def named_grants(
    grants: Sequence[PermissionGrant], catalogue: PermissionCatalogue
) -> tuple[PermissionGrant, ...]:
    """Fill in the name and the consent requirement of every granted permission.

    An application permission arrives as a bare identifier and a delegated one
    as a scope name. Both come out of here carrying the name, the resource it
    belongs to and whether it needed an administrator.
    """
    resolved: list[PermissionGrant] = []
    for grant in grants:
        fact = (
            catalogue.fact_for_id(grant.value)
            if grant.kind == "application"
            else catalogue.fact_for_value(grant.resource_app_id, grant.value)
        )
        resolved.append(
            grant._replace(
                value=fact.value if fact and fact.value else grant.value,
                resource_display_name=(
                    grant.resource_display_name
                    or (fact.resource if fact else "")
                    or catalogue.resource_names.get(grant.resource_app_id, "")
                ),
                admin_consent_required=(
                    grant.admin_consent_required
                    if grant.admin_consent_required is not None
                    else (fact.admin_consent_required if fact else None)
                ),
            )
        )
    return tuple(resolved)


def requested_permission_rows(
    application: ApplicationSummary | None, catalogue: PermissionCatalogue
) -> list[dict[str, Any]]:
    """Return every requested permission, named and with its consent need."""
    if application is None:
        return []
    rows: list[dict[str, Any]] = []
    for request in application.requested_permissions:
        resource = catalogue.resource_names.get(request.resource_app_id, "")
        for kind, identifiers in (
            ("delegated", request.delegated),
            ("application", request.application),
        ):
            for identifier in identifiers:
                fact = catalogue.fact_for_id(identifier)
                rows.append(
                    {
                        "resource_app_id": request.resource_app_id,
                        "resource": resource,
                        "kind": kind,
                        "permission": fact.value if fact else identifier,
                        "permission_id": identifier,
                        "admin_consent_required": (
                            True
                            if kind == "application"
                            else None
                            if fact is None
                            else fact.admin_consent_required
                        ),
                        "resolved": fact is not None,
                    }
                )
    return rows


def matched_grant(
    row: Mapping[str, Any], granted: Sequence[PermissionGrant]
) -> PermissionGrant | None:
    """Return the grant that satisfies one requested permission, if any.

    Matched on the permission name rather than on the identifier, because a
    delegated grant records the name and never the identifier. The resource has
    to agree too where both sides know it: a request records the resource by
    its application id and a grant records it by its object id, so the two are
    compared by the resource name the catalogue resolved for each. Where either
    is unknown the name alone decides, which is the best that can be done and
    is what the identifier form of the report shows.
    """
    wanted_resource = str(row.get("resource") or "")
    for grant in granted:
        if grant.kind != row["kind"]:
            continue
        if grant.value not in (row["permission"], row["permission_id"]):
            continue
        if (
            wanted_resource
            and grant.resource_display_name
            and grant.resource_display_name != wanted_resource
        ):
            continue
        return grant
    return None


def consent_state(
    application: ApplicationSummary | None,
    principal: ServicePrincipalSummary | None,
    catalogue: PermissionCatalogue | None = None,
) -> dict[str, Any]:
    """Say what was asked for, what was granted, and what nobody consented to.

    The difference between the two is where missing admin consent shows up, and
    it is the single most common cause of a permission failure. Three things
    are reported separately because they fail differently. A permission needing
    admin consent and not having it is refused for everybody. A delegated
    permission consented by one person works for them and is refused for
    everybody else, which is the failure only one engineer cannot reproduce. A
    permission granted but never asked for is consent nobody has a record of
    requesting.
    """
    known = catalogue or PermissionCatalogue({}, {}, {})
    requested = requested_permission_rows(application, known)
    granted = tuple(principal.granted_permissions) if principal else ()
    granted_delegated = [item for item in granted if item.kind == "delegated"]
    granted_application = [item for item in granted if item.kind == "application"]
    tenant_wide = [item for item in granted_delegated if item.admin_consent_recorded]
    user_only = [item for item in granted_delegated if not item.admin_consent_recorded]

    outstanding: list[dict[str, Any]] = []
    for row in requested:
        grant = matched_grant(row, granted)
        needs_admin = row["admin_consent_required"]
        if grant is not None and (grant.admin_consent_recorded or not needs_admin):
            continue
        outstanding.append(
            {
                **row,
                "granted": grant is not None,
                "consent_type": grant.consent_type if grant else "",
                "why": (
                    "granted, but consented by one person rather than for the tenant"
                    if grant is not None
                    else "no consent of any kind has been recorded"
                ),
            }
        )
    # Copied rather than shared, because the same object appearing in two
    # lists is rendered as a YAML anchor and a reference, and nobody reading a
    # report should have to know what those mean.
    needing_admin = [dict(row) for row in outstanding if row["admin_consent_required"]]

    return {
        "requested_delegated": sum(
            1 for row in requested if row["kind"] == "delegated"
        ),
        "requested_application": sum(
            1 for row in requested if row["kind"] == "application"
        ),
        "requested": requested,
        "granted_delegated": [item.value for item in granted_delegated],
        "granted_application": [item.value for item in granted_application],
        "granted": [to_payload(item) for item in granted],
        # The headline. Everything below explains it.
        "admin_consent_complete": not needing_admin,
        "admin_consent_granted": bool(granted_application or tenant_wide),
        "without_admin_consent": needing_admin,
        "user_consented_only": [to_payload(item) for item in user_only],
        "not_consented": outstanding,
        "admin_consent_note": consent_note(needing_admin, user_only, known),
    }


def consent_note(
    needing_admin: Sequence[Mapping[str, Any]],
    user_only: Sequence[PermissionGrant],
    catalogue: PermissionCatalogue,
) -> str:
    """Say in one sentence what the consent picture means."""
    parts: list[str] = []
    if needing_admin:
        named = ", ".join(str(row["permission"]) for row in needing_admin)
        parts.append(
            f"{len(needing_admin)} permission(s) need admin consent and do not "
            f"have it: {named}. Every call using one of them is refused."
        )
    if user_only:
        people = ", ".join(
            sorted({item.principal for item in user_only if item.principal})
        )
        parts.append(
            f"{len(user_only)} delegated permission(s) were consented by an "
            "individual rather than for the tenant, so they work for that "
            f"person alone{f' ({people})' if people else ''}."
        )
    if not parts:
        parts.append(
            "Every permission the registration asks for has the consent it needs."
        )
    if catalogue.unresolved:
        parts.append(
            f"{len(catalogue.unresolved)} resource(s) could not be read, so "
            "some permissions are shown as identifiers and their consent "
            "requirement is unknown."
        )
    return " ".join(parts)


def as_mapping(value: Any) -> Mapping[str, Any]:
    """Return a value when it is a mapping, and an empty one when it is not."""
    return value if isinstance(value, Mapping) else {}


def exposed_api(
    payload: Mapping[str, Any],
    config: Config | None = None,
    catalogue: PermissionCatalogue | None = None,
) -> dict[str, Any]:
    """Project what an application exposes to other applications.

    A pre authorised client carries the identifiers of the scopes it may ask
    for. They are this application's own scopes, so they are named from the
    same payload without another call, and naming them is the difference
    between seeing that a client is pre authorised and seeing what for.
    """
    api = as_mapping(payload.get("api"))
    scopes = api.get("oauth2PermissionScopes") or []
    roles = payload.get("appRoles") or []
    own_scopes = {
        text(scope.get("id")): text(scope.get("value"))
        for scope in scopes
        if isinstance(scope, Mapping) and scope.get("id")
    }
    pre_authorized = (
        project_pre_authorized(payload, config) if config is not None else ()
    )
    return {
        "identifier_uris": payload.get("identifierUris") or [],
        "requested_access_token_version": api.get("requestedAccessTokenVersion"),
        # A claims mapping policy assigned to a resource that does not accept
        # mapped claims is ignored, which looks exactly like one that does not
        # work.
        "accept_mapped_claims": api.get("acceptMappedClaims"),
        "delegated_scopes": [
            {
                "value": scope.get("value"),
                "consent": scope.get("type"),
                "admin_consent_required": (
                    text(scope.get("type")) == admin_scope_type(config)
                ),
                "enabled": scope.get("isEnabled"),
                "admin_description": scope.get("adminConsentDescription"),
            }
            for scope in scopes
            if isinstance(scope, Mapping)
        ],
        "application_roles": [
            {
                "value": role.get("value"),
                "display_name": role.get("displayName"),
                "enabled": role.get("isEnabled"),
                "allowed_member_types": role.get("allowedMemberTypes"),
            }
            for role in roles
            if isinstance(role, Mapping)
        ],
        "pre_authorized_applications": [
            {
                "app_id": entry.app_id,
                "display_name": (
                    catalogue.resource_names.get(entry.app_id, "")
                    if catalogue is not None
                    else ""
                ),
                "permissions": [
                    own_scopes.get(identifier, identifier)
                    for identifier in entry.permissions
                ],
            }
            for entry in pre_authorized
        ],
    }


def admin_scope_type(config: Config | None) -> str:
    """Return the scope type that means only an administrator may consent."""
    if config is None:
        return ""
    return config.fields.classification.admin_consent_scope_type


def urls(
    application: ApplicationSummary | None,
    principal: ServicePrincipalSummary | None,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Gather every address the application is registered with.

    A redirect that does not match is compared byte for byte, so they are shown
    exactly as registered rather than tidied.
    """
    web = as_mapping(payload.get("web"))
    return {
        "web_redirect_uris": list(application.redirect_uris.web) if application else [],
        "single_page_redirect_uris": (
            list(application.redirect_uris.single_page) if application else []
        ),
        "public_client_redirect_uris": (
            list(application.redirect_uris.public_client) if application else []
        ),
        "logout_url": web.get("logoutUrl"),
        "home_page_url": web.get("homePageUrl"),
        "implicit_grant": web.get("implicitGrantSettings"),
        "saml_reply_urls": list(principal.reply_urls) if principal else [],
        "service_principal_names": (
            list(principal.service_principal_names) if principal else []
        ),
    }


def search_gallery(
    session: Session, config: Config, term: str, limit: int
) -> tuple[tuple[dict[str, Any], ...], str]:
    """Search the gallery by name.

    The endpoint filters on a prefix and is case sensitive, and does not page,
    so a bare substring finds nothing. The first word is used as the prefix, in
    the case given and then capitalised, and the whole term is matched against
    what comes back.
    """
    if not term:
        rows = get_collection(session, config, "application_templates", limit=limit)
        return rows, ""
    prefix = term.split()[0]
    for candidate in dict.fromkeys([prefix, prefix.capitalize(), prefix.upper()]):
        rows = get_collection(
            session,
            config,
            "application_templates",
            filter_expression=(f"startswith(displayName,'{odata_literal(candidate)}')"),
        )
        if not rows:
            continue
        lowered = term.lower()
        matched = tuple(
            row
            for row in rows
            if lowered in str(row.get("displayName", "")).lower()
            or lowered in str(row.get("publisher", "")).lower()
        )
        if matched:
            return matched[:limit], ""
        # The prefix found applications and the rest of the term did not. Those
        # are still the nearest thing to what was asked for, and saying so is
        # more use than an empty table.
        return (
            rows[:limit],
            f"Nothing matched {term!r} exactly. These start with {candidate!r}.",
        )
    return (), f"Nothing in the gallery starts with {prefix!r}."


def permission_names(
    session: Session, config: Config, resource_app_ids: Sequence[str]
) -> dict[str, str]:
    """Map permission identifiers to their names, for each resource named.

    A requested permission is recorded as a bare identifier. Nobody can read
    those, and the name is what the remediation will tell them to grant, so it
    is worth one call per resource to resolve them. The catalogue does the
    reading; this is the name half of what it returns.
    """
    catalogue = read_permission_catalogue(session, config, app_ids=resource_app_ids)
    return {key: fact.value for key, fact in catalogue.by_id.items()}


def named_permissions(
    application: ApplicationSummary | None, names: Mapping[str, str]
) -> list[dict[str, Any]]:
    """Return the requested permissions with their names rather than identifiers."""
    if application is None:
        return []
    return [
        {
            "resource_app_id": request.resource_app_id,
            "delegated": [names.get(item, item) for item in request.delegated],
            "application": [names.get(item, item) for item in request.application],
        }
        for request in application.requested_permissions
    ]


def inspect(
    session: Session,
    config: Config,
    token: Callable[[], str] | None = None,
    *,
    target: str,
    kinds: Sequence[str] = (),
    catalogue: Catalogue | None = None,
) -> dict[str, Any]:
    """Gather everything about one application, for reading.

    Both objects are fetched, because a failure can come from either, and an
    engineer told only about one will look in the wrong place. A catalogue that
    has already been read is used rather than reading the directory again.
    """
    known = catalogue or read_catalogue(session, config, token)
    applications = matching(known.applications, target, kinds)
    principals = matching(known.principals, target, kinds)
    if not applications and not principals:
        raise ApiCallError(_not_found(target))

    # The catalogue holds names and identifiers. The one being inspected is
    # read in full, on its own, which is two calls rather than one per object
    # in the tenant.
    application: ApplicationSummary | None = None
    payload: Mapping[str, Any] = {}
    if applications:
        application, payload = read_one_application_with_payload(
            session, config, applications[0]
        )
    principal = principals[0] if principals else None
    if application and not principal:
        principal = next(
            (item for item in known.principals if item.app_id == application.app_id),
            None,
        )
    principal = read_one_principal(session, config, principal)

    log.info(
        "inspecting %s",
        application.display_name if application else target,
        extra={"application_id": application.app_id if application else ""},
    )
    # Details are fetched for the one application being inspected, not for
    # every application in the tenant. On a directory of several hundred the
    # difference is two calls against several hundred.
    application = with_owners_and_federation(session, config, application)
    # Every resource the application asks something of, and every resource it
    # has actually been granted something against. Read once, here, so that the
    # requested permissions, the granted ones and the assignments are all named
    # rather than left as identifiers.
    permissions = read_permission_catalogue(
        session,
        config,
        app_ids=[
            request.resource_app_id
            for request in (application.requested_permissions if application else ())
        ],
        object_ids=[
            grant.resource_app_id
            for grant in (principal.granted_permissions if principal else ())
        ],
    )
    if principal is not None:
        principal = principal._replace(
            granted_permissions=named_grants(
                principal.granted_permissions, permissions
            ),
            assignments=named_app_role_assignments(
                principal.assignments, app_role_names(payload, principal)
            ),
        )
    portal = config.endpoints.portal
    return {
        "identity": {
            "display_name": (
                application.display_name
                if application
                else principal.display_name
                if principal
                else target
            ),
            "application_id": (
                application.app_id
                if application
                else principal.app_id
                if principal
                else ""
            ),
            "registration_object_id": application.object_id if application else None,
            "enterprise_object_id": principal.object_id if principal else None,
            "application_type": (
                application.application_type
                if application
                else principal.application_type
                if principal
                else "unknown"
            ),
            "created": application.created if application else None,
        },
        "sign_in": {
            "audience": application.sign_in_audience if application else None,
            "audience_meaning": application.audience_label if application else None,
            "account_enabled": principal.account_enabled if principal else None,
            "assignment_required": (
                principal.app_role_assignment_required if principal else None
            ),
            "single_sign_on_mode": (
                principal.saml.preferred_single_sign_on_mode
                if principal and principal.saml
                else None
            ),
            "gallery_application": (
                principal.saml.is_gallery if principal and principal.saml else None
            ),
        },
        "single_sign_on": single_sign_on_view(principal, payload, config),
        "urls": urls(application, principal, payload),
        "exposes": exposed_api(payload, config, permissions),
        "permissions": {
            "requested": named_permissions(
                application,
                {key: fact.value for key, fact in permissions.by_id.items()},
            ),
            "consent": consent_state(application, principal, permissions),
        },
        "access": access_view(principal, config),
        "credentials": [to_payload(item) for item in application.credentials]
        if application
        else [],
        "federated_credentials": [
            to_payload(item) for item in application.federated_credentials
        ]
        if application
        else [],
        "owners": list(application.owners) if application else [],
        "tags": list(principal.tags) if principal else [],
        "provisioning": provisioning_view(application, principal, payload, config),
        "portal": {
            "registration": portal_link(
                {"app_id": application.app_id if application else ""},
                "app_id",
                config,
            ),
            "enterprise_application": (
                portal.enterprise_application.format(object_id=principal.object_id)
                if principal
                else None
            ),
        },
    }


def app_role_names(
    payload: Mapping[str, Any], principal: ServicePrincipalSummary | None
) -> dict[str, str]:
    """Map the roles this application defines onto their names.

    An assignment records the role identifier. The roles are defined on the
    application itself, so no extra call is needed to read them back.
    """
    _ = principal
    return {
        text(role.get("id")): text(role.get("value")) or text(role.get("displayName"))
        for role in (payload.get("appRoles") or [])
        if isinstance(role, Mapping) and role.get("id")
    }


def access_view(
    principal: ServicePrincipalSummary | None, config: Config
) -> dict[str, Any]:
    """Say who may use this application, and what its own identity belongs to.

    Assignment is the half of authorisation that consent says nothing about.
    Where the application requires assignment, an identity that is not assigned
    is refused however much has been consented, and the assignment is far more
    often to a security group than to a person. The groups are listed by name,
    with whether membership is a rule rather than a list, because a dynamic
    group grants and revokes access without anybody touching the application.
    """
    if principal is None:
        return {
            "assignment_required": None,
            "note": (
                "There is no enterprise application, so nothing is assigned to "
                "anything. Only the registration exists."
            ),
        }
    rules = config.fields.classification
    assignments = principal.assignments
    groups = [
        item
        for item in assignments
        if item.principal_type == rules.principal_types["group"]
    ]
    users = [
        item
        for item in assignments
        if item.principal_type == rules.principal_types["user"]
    ]
    principals = [
        item
        for item in assignments
        if item.principal_type == rules.principal_types["service_principal"]
    ]
    member_of = principal.member_of
    return {
        "assignment_required": principal.app_role_assignment_required,
        "assignment_meaning": (
            "Only the users, groups and applications assigned below may sign "
            "in. Anybody else is refused whatever has been consented."
            if principal.app_role_assignment_required
            else "Assignment is not required, so anybody in the tenant the "
            "consent covers may sign in. The assignments below grant roles "
            "rather than admission."
        ),
        "assigned_total": len(assignments),
        "security_groups": [to_payload(item) for item in groups],
        "users": [to_payload(item) for item in users],
        "applications": [to_payload(item) for item in principals],
        "member_of": {
            "security_groups": [
                to_payload(item) for item in security_groups(member_of, config)
            ],
            "directory_roles": [
                to_payload(item)
                for item in memberships_of_kind(member_of, "directory-role")
            ],
            "administrative_units": [
                to_payload(item)
                for item in memberships_of_kind(member_of, "administrative-unit")
            ],
            "note": (
                "Groups and roles this application's own identity belongs to. "
                "Access held this way is granted to the group rather than to "
                "the application, so nothing on the application itself records "
                "it."
            ),
        },
        "note": (
            "Nothing is assigned to this application."
            if not assignments
            else f"{len(groups)} security group(s), {len(users)} user(s) and "
            f"{len(principals)} application(s) are assigned."
        ),
    }


def single_sign_on_view(
    principal: ServicePrincipalSummary | None,
    payload: Mapping[str, Any],
    config: Config,
) -> dict[str, Any]:
    """Report the single sign on configuration and what silently rewrites a token.

    A SAML integration breaks on the parts a registration does not show: which
    of several certificates actually signs, whether anybody is warned before it
    expires, and whether a policy is rewriting the token on the way out. All
    three are here whichever protocol the application uses, because a claims
    mapping policy applies to an OpenID Connect token just as it does to a SAML
    assertion.
    """
    saml = principal.saml if principal else None
    policies = principal.policies if principal else ()
    mapping = config.fields.application
    view: dict[str, Any] = {
        "mode": (
            principal.saml.preferred_single_sign_on_mode
            if principal and principal.saml
            else text(
                pluck(
                    payload,
                    config.fields.service_principal["preferred_single_sign_on_mode"],
                )
            )
        ),
        "accept_mapped_claims": pluck(payload, mapping["accept_mapped_claims"]),
        "policies": [to_payload(item) for item in policies],
        "policy_note": policy_note(policies, payload, config),
    }
    if saml is None:
        return view
    view["saml"] = {
        **to_payload(saml),
        "signing_note": signing_note(saml),
    }
    return view


def policy_note(
    policies: Sequence[AssignedPolicy],
    payload: Mapping[str, Any],
    config: Config,
) -> str:
    """Say what the policies assigned to an application actually do."""
    if not policies:
        return (
            "No policy is assigned, so the token carries what the registration "
            "says it carries."
        )
    kinds = ", ".join(sorted({item.kind for item in policies}))
    note = (
        f"{len(policies)} policy assignment(s): {kinds}. None of this is "
        "recorded on the registration, so a token that does not match the "
        "registration is explained here."
    )
    claims = config.fields.classification.claims_mapping_policy_kind
    accepts = pluck(payload, config.fields.application["accept_mapped_claims"])
    if any(item.kind == claims for item in policies) and not accepts:
        note = (
            f"{note} A claims mapping policy is assigned and the application "
            "does not accept mapped claims, so the policy is ignored, which "
            "looks exactly like a policy that does not work. Set "
            "acceptMappedClaims, or sign the token with a custom key."
        )
    return note


def signing_note(saml: Any) -> str:
    """Say which certificate signs, and whether anybody is warned before it goes."""
    parts: list[str] = []
    certificates = saml.signing_certificates
    if saml.preferred_signing_key_thumbprint:
        parts.append(
            "The certificate signing assertions is the one with thumbprint "
            f"{saml.preferred_signing_key_thumbprint}."
        )
    elif len(certificates) > 1:
        parts.append(
            f"There are {len(certificates)} signing certificates and no "
            "preferred thumbprint, so which one signs is Entra's choice rather "
            "than a recorded decision."
        )
    if not saml.notification_email_addresses:
        parts.append(
            "No address is registered for expiry notification, so nobody is "
            "warned before the signing certificate expires and single sign on "
            "stops."
        )
    return " ".join(parts)


def _not_found(target: str) -> Any:
    """Return the error raised when nothing matched."""
    from entrascope.models import ApiError

    return ApiError(
        status=0,
        code="NotFound",
        message=(
            f"Nothing matched {target!r}. Try part of a display name, an "
            "application id or an object id, or run entrascope inspect with no "
            "argument to choose from a list."
        ),
        source="inspect",
    )


def read_one_application(
    session: Session, config: Config, summary: ApplicationSummary
) -> ApplicationSummary:
    """Read one application in full and project it."""
    payload = raw_application(session, config, summary)
    return project_application(payload, config) if payload else summary


def read_one_application_with_payload(
    session: Session, config: Config, summary: ApplicationSummary
) -> tuple[ApplicationSummary, Mapping[str, Any]]:
    """Read one application once, returning both the projection and the payload.

    The projection covers most of the report and the untouched payload covers
    the rest. Reading the object twice to get both was a wasted call on every
    single inspection.
    """
    payload = raw_application(session, config, summary)
    if not payload:
        return summary, {}
    return project_application(payload, config), payload


def read_one_principal(
    session: Session, config: Config, summary: ServicePrincipalSummary | None
) -> ServicePrincipalSummary | None:
    """Read one enterprise application in full, with everything around it.

    Four collections, and each answers a different question. appRoleAssignments
    is what this application may do to other resources. oauth2PermissionGrants
    is what a person has consented to on its behalf, and whether they did so
    for themselves or for the tenant. appRoleAssignedTo is who may use it, which
    is where the security groups are. memberOf is what its own identity belongs
    to, which is how it can hold access nothing about the application mentions.
    """
    if summary is None or not summary.object_id:
        return summary
    try:
        payload = get_object(
            session,
            config,
            "service_principal_by_id",
            path_parameters={"object_id": summary.object_id},
        )
    except ApiCallError as error:
        log.debug(
            "could not read the enterprise application: %s", error.error.summary()
        )
        return summary
    parameters = {"object_id": summary.object_id}
    return project_service_principal(
        payload,
        config,
        grants=read_grants(session, config, summary.object_id),
        assignments=read_collection(session, config, "granted_app_roles", parameters),
        assigned_to=read_collection(
            session, config, "app_role_assignments", parameters
        ),
        member_of=read_collection(
            session, config, "service_principal_member_of", parameters
        ),
        policies=read_policies(session, config, parameters),
    )


#: The policies that can be assigned to an enterprise application, and what
#: this tool calls each. Every one changes a token without the registration
#: recording that it does.
POLICY_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("claims_mapping_policies", "claims mapping"),
    ("home_realm_discovery_policies", "home realm discovery"),
    ("token_lifetime_policies", "token lifetime"),
)


def read_policies(
    session: Session, config: Config, parameters: Mapping[str, str]
) -> tuple[AssignedPolicy, ...]:
    """Read every policy assigned to one enterprise application.

    Each kind is its own collection and each may be refused on its own, so a
    tenant that grants one and not another still reports the one it granted.
    """
    found: list[AssignedPolicy] = []
    for endpoint, kind in POLICY_ENDPOINTS:
        rows = read_collection(session, config, endpoint, parameters)
        found.extend(project_policies(rows, kind, config))
    return tuple(found)


def read_grants(
    session: Session, config: Config, object_id: str
) -> tuple[dict[str, Any], ...]:
    """Read the delegated consent recorded for one application, tolerating a refusal."""
    try:
        return grants_for_client(session, config, object_id)
    except ApiCallError as error:
        log.debug("could not read delegated consent: %s", error.error.summary())
        return ()


def with_owners_and_federation(
    session: Session,
    config: Config,
    application: ApplicationSummary | None,
) -> ApplicationSummary | None:
    """Fill in the details that need a call of their own, for one application."""
    if application is None or not application.object_id:
        return application
    parameters = {"object_id": application.object_id}
    owners = read_collection(session, config, "application_owners", parameters)
    federated = read_collection(
        session, config, "federated_identity_credentials", parameters
    )
    return application._replace(
        owners=owner_names(owners),
        federated_credentials=project_federated_credentials(federated),
        application_type=classify_application(
            application.redirect_uris,
            application.credentials,
            project_federated_credentials(federated),
            application.exposes_api,
        ),
    )


def read_collection(
    session: Session,
    config: Config,
    endpoint: str,
    parameters: Mapping[str, str],
) -> tuple[dict[str, Any], ...]:
    """Read one collection for one object, tolerating a refusal."""
    try:
        return get_collection(session, config, endpoint, path_parameters=parameters)
    except ApiCallError as error:
        log.debug("could not read %s: %s", endpoint, error.error.summary())
        return ()


def raw_application(
    session: Session,
    config: Config,
    application: ApplicationSummary | None,
) -> Mapping[str, Any]:
    """Fetch the untouched Graph payload, for the parts no projection covers."""
    if application is None or not application.object_id:
        return {}
    try:
        # A single object, so no collection parameters and no page size.
        return get_object(
            session,
            config,
            "application_by_id",
            path_parameters={"object_id": application.object_id},
        )
    except ApiCallError as error:
        log.debug("could not read the application payload: %s", error.error.summary())
        return {}


def summarise_target(report: Mapping[str, Any]) -> str:
    """Return a one line description of what was inspected."""
    identity = report.get("identity", {})
    return (
        f"{text(identity.get('display_name'))} "
        f"({text(identity.get('application_type'))})"
    )


def platform_facts(
    application: ApplicationSummary | None,
    principal: ServicePrincipalSummary | None,
    payload: Mapping[str, Any],
    config: Config,
) -> dict[str, Any]:
    """Reduce an application to the facts the type rules are written against.

    Each fact is something registered on the object, so the mapping can be
    checked by anybody reading the same registration.
    """
    mapping = config.fields.application
    redirects = application.redirect_uris if application else None
    credentials = application.credentials if application else ()
    kinds = {item.kind for item in credentials}
    known = pluck(payload, mapping["known_client_applications"]) or []
    exposed = exposed_api(payload, config)
    platform = "none"
    if redirects and redirects.single_page:
        platform = "spa"
    elif redirects and redirects.web:
        platform = "web"
    elif redirects and redirects.public_client:
        platform = "publicClient"
    fallback_public = pluck(payload, mapping["is_fallback_public_client"])
    return {
        "platform": platform,
        # Whether Entra treats this as a public client when the token request
        # does not say. A confidential client with this true is refused when it
        # presents a secret; a native client with it false is refused when it
        # does not.
        "fallback_public_client": bool(fallback_public),
        "credentials": (
            "certificate"
            if kinds == {"certificate"}
            else "secret"
            if "secret" in kinds
            else "none"
        ),
        "federated": bool(application.federated_credentials) if application else False,
        "exposes_api": bool(
            exposed["delegated_scopes"]
            or exposed["application_roles"]
            or exposed["identifier_uris"]
        ),
        "known_client_applications": bool(known),
        "sso_mode": (
            principal.saml.preferred_single_sign_on_mode
            if principal and principal.saml
            else ""
        ),
        "gallery": bool(principal.saml.is_gallery)
        if principal and principal.saml
        else False,
        "service_principal_type": (
            principal.service_principal_type if principal else ""
        ),
    }


def rule_matches(rule: Mapping[str, Any], facts: Mapping[str, Any]) -> bool:
    """Return whether every condition of one rule holds.

    The value ``any`` means the fact must be present and not the word none,
    which is how a rule says "holds a credential of some kind".
    """
    for name, expected in rule.items():
        actual = facts.get(name)
        if expected == "any":
            if not actual or actual == "none":
                return False
        elif isinstance(expected, bool):
            if bool(actual) is not expected:
                return False
        elif actual != expected:
            return False
    return True


def classify_app_type(facts: Mapping[str, Any], config: Config) -> dict[str, Any]:
    """Map an application onto the provisioning vocabulary.

    The vocabulary is configuration, and its status is reported alongside the
    answer, because a derived name must not be mistaken for a settled one.
    """
    vocabulary = config.capabilities.provisioning
    for rule in vocabulary.app_types:
        if rule_matches(rule.when, facts):
            return {
                "app_type": rule.name,
                "meaning": rule.description.strip(),
                "matched_on": dict(rule.when)
                or "nothing matched, this is the fallback",
                "vocabulary_status": vocabulary.app_type_vocabulary.status,
                "vocabulary_note": vocabulary.app_type_vocabulary.derived_from.strip(),
                "evidence": dict(facts),
            }
    return {
        "app_type": "UNKNOWN",
        "vocabulary_status": vocabulary.app_type_vocabulary.status,
        "evidence": dict(facts),
    }


def provisioning_view(
    application: ApplicationSummary | None,
    principal: ServicePrincipalSummary | None,
    payload: Mapping[str, Any],
    config: Config,
) -> dict[str, Any]:
    """Report the application in the words the provisioner creates it with.

    Reading it back in the same vocabulary is what lets the live object be
    compared against the parameters that were meant to produce it.
    """
    mapping = config.fields.application
    redirects = application.redirect_uris if application else None
    web = as_mapping(payload.get("web"))
    exposed = exposed_api(payload, config)
    facts = platform_facts(application, principal, payload, config)
    outside = config.capabilities.provisioning.outside_the_vocabulary
    kind = (
        application.application_type
        if application
        else (principal.application_type if principal else "unknown")
    )
    return {
        **classify_app_type(facts, config),
        "outside_the_provisioner_vocabulary": outside.get(kind, "").strip() or None,
        "platforms": {
            "spa": {
                "enabled": bool(redirects and redirects.single_page),
                "redirectUris": list(redirects.single_page) if redirects else [],
            },
            "web": {
                "enabled": bool(redirects and redirects.web),
                "redirectUris": list(redirects.web) if redirects else [],
                "implicitGrant": web.get("implicitGrantSettings"),
            },
            "publicClient": {
                "enabled": bool(redirects and redirects.public_client),
                "redirectUris": list(redirects.public_client) if redirects else [],
            },
        },
        "exposedApi": {
            "enabled": facts["exposes_api"],
            "identifierUri": (exposed["identifier_uris"] or [None])[0],
            "scopes": exposed["delegated_scopes"],
            "appRoles": exposed["application_roles"],
        },
        "obo": {
            "enabled": facts["known_client_applications"],
            "knownClientApplicationIds": list(
                pluck(payload, mapping["known_client_applications"]) or []
            ),
        },
        "isFallbackPublicClient": pluck(payload, mapping["is_fallback_public_client"]),
        "signInAudience": application.sign_in_audience if application else None,
        "tokenVersion": application.requested_access_token_version
        if application
        else None,
        "groupMembershipClaims": pluck(payload, mapping["group_membership_claims"]),
        "optionalClaims": pluck(payload, mapping["optional_claims"]),
        "tags": strings(pluck(payload, mapping["tags"])),
        "notes": pluck(payload, mapping["notes"]),
        "serviceManagementReference": pluck(
            payload, mapping["service_management_reference"]
        ),
        "publisherDomain": pluck(payload, mapping["publisher_domain"]),
        "verifiedPublisher": pluck(payload, mapping["verified_publisher"]),
        "disabledByMicrosoft": pluck(payload, mapping["disabled_by_microsoft"]),
    }
