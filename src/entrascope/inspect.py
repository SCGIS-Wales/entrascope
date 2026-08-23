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
    owner_names,
    pluck,
    project_application,
    project_federated_credentials,
    project_service_principal,
    strings,
    text,
)
from entrascope.graph import get_collection, get_object, odata_literal
from entrascope.http import Session
from entrascope.logger import get_logger
from entrascope.models import (
    ApiCallError,
    ApplicationSummary,
    ServicePrincipalSummary,
)
from entrascope.render import portal_link, to_payload

log = get_logger(__name__)

#: Graph reports a delegated permission as Scope and an application permission
#: as Role inside an app role assignment.
CONSENT_ALL = "AllPrincipals"


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

    def choices(self) -> tuple[tuple[str, str], ...]:
        """Return identifier and label for each, sorted by name.

        The names are padded to a common width so that the identifiers line up
        in a column. A list of several hundred where the identifier starts at a
        different place on every line is a list nobody can read down.
        """
        seen = {item.app_id for item in self.applications}
        named: list[tuple[str, str, str]] = [
            (item.app_id or item.object_id, item.display_name, "")
            for item in self.applications
        ]
        named.extend(
            (item.app_id or item.object_id, item.display_name, "enterprise")
            for item in self.principals
            if item.app_id not in seen
        )
        width = min(max((len(name) for _, name, _ in named), default=0), NAME_WIDTH)
        rows = [
            (
                key,
                f"{shorten(name, width):<{width}}  {key}"
                + (f"  [{marker}]" if marker else ""),
            )
            for key, name, marker in named
        ]
        return tuple(sorted(rows, key=lambda pair: pair[1].lower()))


#: The widest a name is allowed to be before the identifier column. Long
#: enough for almost every display name, short enough that the identifiers are
#: still on the screen.
NAME_WIDTH = 56


def shorten(name: str, width: int) -> str:
    """Return a name that fits, with an ellipsis where it was cut."""
    return name if len(name) <= width else name[: width - 1] + "\u2026"


#: All the chooser needs. Reading whole objects to draw a list of names is the
#: difference between answering and appearing to hang.
CHOOSER_FIELDS = ("id", "appId", "displayName")
PRINCIPAL_CHOOSER_FIELDS = (
    "id",
    "appId",
    "displayName",
    "servicePrincipalType",
    "appOwnerOrganizationId",
)


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
            session, config, "applications", select=CHOOSER_FIELDS
        )
    )
    principals = tuple(
        project_service_principal(payload, config)
        for payload in get_collection(
            session, config, "service_principals", select=PRINCIPAL_CHOOSER_FIELDS
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


def consent_state(
    application: ApplicationSummary | None,
    principal: ServicePrincipalSummary | None,
) -> dict[str, Any]:
    """Say what was asked for and what was actually granted.

    The difference between the two is where missing admin consent shows up, and
    it is the single most common cause of a permission failure.
    """
    requested_delegated = sum(
        len(item.delegated)
        for item in (application.requested_permissions if application else ())
    )
    requested_application = sum(
        len(item.application)
        for item in (application.requested_permissions if application else ())
    )
    granted = principal.granted_permissions if principal else ()
    granted_delegated = [item for item in granted if item.kind == "delegated"]
    granted_application = [item for item in granted if item.kind == "application"]
    tenant_wide = [item for item in granted_delegated if item.principal == "all users"]
    return {
        "requested_delegated": requested_delegated,
        "requested_application": requested_application,
        "granted_delegated": [item.value for item in granted_delegated],
        "granted_application": [item.value for item in granted_application],
        "admin_consent_granted": bool(granted_application or tenant_wide),
        "admin_consent_note": (
            "Application permissions and tenant wide delegated grants both "
            "require admin consent. Nothing granted here means consent was "
            "never recorded, whatever the registration asks for."
            if not (granted_application or tenant_wide)
            else "Consent has been recorded for the grants listed."
        ),
    }


def as_mapping(value: Any) -> Mapping[str, Any]:
    """Return a value when it is a mapping, and an empty one when it is not."""
    return value if isinstance(value, Mapping) else {}


def exposed_api(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Project what an application exposes to other applications."""
    api = as_mapping(payload.get("api"))
    scopes = api.get("oauth2PermissionScopes") or []
    roles = payload.get("appRoles") or []
    return {
        "identifier_uris": payload.get("identifierUris") or [],
        "requested_access_token_version": api.get("requestedAccessTokenVersion"),
        "delegated_scopes": [
            {
                "value": scope.get("value"),
                "consent": scope.get("type"),
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
            entry.get("appId")
            for entry in (api.get("preAuthorizedApplications") or [])
            if isinstance(entry, Mapping)
        ],
    }


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
    is worth one call per resource to resolve them.
    """
    resolved: dict[str, str] = {}
    for app_id in dict.fromkeys(resource_app_ids):
        if not app_id:
            continue
        try:
            rows = get_collection(
                session,
                config,
                "service_principal_by_app_id",
                path_parameters={"app_id": app_id},
            )
        except ApiCallError as error:
            log.debug("could not resolve %s: %s", app_id, error.error.summary())
            continue
        for row in rows:
            for scope in row.get("oauth2PermissionScopes") or []:
                if isinstance(scope, Mapping) and scope.get("id"):
                    resolved[str(scope["id"])] = str(scope.get("value", ""))
            for role in row.get("appRoles") or []:
                if isinstance(role, Mapping) and role.get("id"):
                    resolved[str(role["id"])] = str(role.get("value", ""))
    return resolved


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
    application = (
        read_one_application(session, config, applications[0]) if applications else None
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
    payload = raw_application(session, config, application)
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
        "urls": urls(application, principal, payload),
        "exposes": exposed_api(payload),
        "permissions": {
            "requested": named_permissions(
                application,
                permission_names(
                    session,
                    config,
                    [
                        request.resource_app_id
                        for request in (
                            application.requested_permissions if application else ()
                        )
                    ],
                ),
            ),
            "consent": consent_state(application, principal),
        },
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
    if not summary.object_id:
        return summary
    try:
        payload = get_object(
            session,
            config,
            "application_by_id",
            path_parameters={"object_id": summary.object_id},
        )
    except ApiCallError as error:
        log.debug("could not read the application: %s", error.error.summary())
        return summary
    return project_application(payload, config)


def read_one_principal(
    session: Session, config: Config, summary: ServicePrincipalSummary | None
) -> ServicePrincipalSummary | None:
    """Read one enterprise application in full and project it."""
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
    grants = read_collection(
        session, config, "app_role_assignments", {"object_id": summary.object_id}
    )
    return project_service_principal(payload, config, assignments=grants)


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
    exposed = exposed_api(payload)
    platform = "none"
    if redirects and redirects.single_page:
        platform = "spa"
    elif redirects and redirects.web:
        platform = "web"
    elif redirects and redirects.public_client:
        platform = "publicClient"
    return {
        "platform": platform,
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
    exposed = exposed_api(payload)
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
