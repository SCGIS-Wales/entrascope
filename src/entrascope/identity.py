"""Who entrascope is signed in as, and what that identity can actually do.

Every failure diagnosis starts with this question and most people answer it
wrong, because the identity a tool authenticates as is rarely the one the
engineer is thinking of. This reports the tenant, the identity, what the token
grants, the directory roles it holds, the administrative units that bound it,
and the conditional access policies that could stand in its way.

Every lookup here can fail on its own, on a tenant that has not granted
everything, and a failure in one must not empty the rest of the report.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from azure.core.credentials import TokenCredential

from entrascope.capabilities import claim_values, decode_claims
from entrascope.config import Config
from entrascope.discovery import text
from entrascope.graph import (
    arm_token_provider,
    get_collection,
    get_object,
    graph_token_provider,
    token_provider,
)
from entrascope.http import Session, build_session
from entrascope.logger import get_logger
from entrascope.models import ApiCallError, AuthContext

log = get_logger(__name__)

#: Claims worth reporting from an access token.
CLAIMS_OF_INTEREST = ("aud", "iss", "tid", "azp", "appid", "oid", "sub", "upn")

#: Object types Graph returns from a memberOf call.
ROLE_TYPE = "#microsoft.graph.directoryRole"
GROUP_TYPE = "#microsoft.graph.group"
UNIT_TYPE = "#microsoft.graph.administrativeUnit"

#: An app role assignment with this identifier carries no application
#: permission. It records access to the application, nothing more.
NO_APP_ROLE = "00000000-0000-0000-0000-000000000000"


def safely(
    call: Callable[[], Any],
    notes: list[str],
    description: str,
    default: Any,
    needs: str = "",
) -> Any:
    """Run one lookup, recording a refusal rather than failing the report.

    An identity is usually granted some of what the report asks for and not
    all of it, and an application credential is granted less than a person is.
    A refusal names the grant that would have answered it, because a report
    saying only that something was denied leaves the reader no better off.
    """
    try:
        return call()
    except ApiCallError as error:
        note = f"{description}: {error.error.summary()}"
        if needs:
            note = f"{note}. Grant {needs} to see this."
        notes.append(note)
        return default


def needed_for(config: Config, lookup: str) -> str:
    """Return the grant a part of the report needs, if configuration names one."""
    return config.capabilities.lookup_permissions.get(lookup, "")


def membership(rows: Sequence[Mapping[str, Any]], kind: str) -> list[str]:
    """Return the display names of one kind of membership."""
    return [
        text(row.get("displayName") or row.get("id"))
        for row in rows
        if row.get("@odata.type") == kind
    ]


def tenant_details(
    session: Session, config: Config, notes: list[str]
) -> dict[str, Any]:
    """Return which tenant is being queried, by name as well as identifier."""
    rows = safely(
        lambda: get_collection(session, config, "organization"),
        notes,
        "Tenant details",
        (),
        needed_for(config, "tenant"),
    )
    if not rows:
        return {}
    row = rows[0]
    domains = [
        text(entry.get("name"))
        for entry in row.get("verifiedDomains") or []
        if isinstance(entry, Mapping) and entry.get("isDefault")
    ]
    return {
        "tenant_id": text(row.get("id")),
        "display_name": text(row.get("displayName")),
        "default_domain": domains[0] if domains else "",
        "country": text(row.get("countryLetterCode")),
    }


def reachable_tenants(
    config: Config, credential: TokenCredential, notes: list[str]
) -> list[dict[str, str]]:
    """Return every tenant this identity can reach.

    Azure Resource Manager knows this and Microsoft Graph does not, so it takes
    its own token. An identity that cannot reach Resource Manager simply gets
    an empty list and a note.
    """
    azure = config.endpoints.azure
    url = (
        f"{azure.arm_base_url}{azure.paths['tenants']}"
        f"?api-version={azure.tenants_api_version}"
    )
    session = build_session(config, arm_token_provider(config, credential))
    try:
        body = safely(
            lambda: _read(session, url, config),
            notes,
            "Reachable tenants",
            {},
            needed_for(config, "reachable_tenants"),
        )
    finally:
        session.close()
    return [
        {
            "tenant_id": text(row.get("tenantId")),
            "display_name": text(row.get("displayName")),
            "domain": text(row.get("defaultDomain")),
        }
        for row in body.get("value", [])
        if isinstance(row, Mapping)
    ]


def _read(session: Session, url: str, config: Config) -> dict[str, Any]:
    """Read one absolute URL as JSON, through the shared transport."""
    from entrascope.http import get_json

    return get_json(session, url, config, source="arm")


def signed_in_user(
    session: Session, config: Config, notes: list[str]
) -> dict[str, Any]:
    """Return the person a delegated session belongs to, and what bounds them."""
    profile = safely(
        lambda: get_object(session, config, "me"),
        notes,
        "Signed in user",
        {},
        needed_for(config, "signed_in_user"),
    )
    memberships = safely(
        lambda: get_collection(session, config, "me_member_of"),
        notes,
        "Directory roles and groups",
        (),
        needed_for(config, "memberships"),
    )
    return {
        "object_id": text(profile.get("id")),
        "display_name": text(profile.get("displayName")),
        "user_principal_name": text(profile.get("userPrincipalName")),
        "directory_roles": membership(memberships, ROLE_TYPE),
        "administrative_units": membership(memberships, UNIT_TYPE),
        "group_count": len(membership(memberships, GROUP_TYPE)),
    }


def service_principal_identity(
    session: Session, config: Config, app_id: str, notes: list[str]
) -> dict[str, Any]:
    """Return the enterprise application an application token belongs to."""
    rows = safely(
        lambda: get_collection(
            session,
            config,
            "service_principal_by_app_id",
            path_parameters={"app_id": app_id},
        ),
        notes,
        "Service principal",
        (),
        needed_for(config, "service_principal"),
    )
    if not rows:
        return {}
    row = rows[0]
    object_id = text(row.get("id"))
    memberships = safely(
        lambda: get_collection(
            session,
            config,
            "service_principal_member_of",
            path_parameters={"object_id": object_id},
        ),
        notes,
        "Directory roles and groups",
        (),
        needed_for(config, "memberships"),
    )
    granted = safely(
        lambda: get_collection(
            session,
            config,
            "granted_app_roles",
            path_parameters={"object_id": object_id},
        ),
        notes,
        "Granted application permissions",
        (),
        needed_for(config, "granted_permissions"),
    )
    return {
        "object_id": object_id,
        "display_name": text(row.get("displayName")),
        "application_id": app_id,
        "account_enabled": row.get("accountEnabled"),
        "directory_roles": membership(memberships, ROLE_TYPE),
        "administrative_units": membership(memberships, UNIT_TYPE),
        "group_count": len(membership(memberships, GROUP_TYPE)),
        "granted_app_role_assignments": [
            {
                "resource": text(item.get("resourceDisplayName")),
                "app_role_id": text(item.get("appRoleId")),
                "meaning": (
                    "access to the application, carrying no permission"
                    if text(item.get("appRoleId")) == NO_APP_ROLE
                    else "an application permission"
                ),
            }
            for item in granted
        ],
    }


def conditional_access(
    session: Session, config: Config, notes: list[str]
) -> dict[str, Any]:
    """Summarise the conditional access policies in force.

    Whether a given policy applies to a given sign in is decided by Entra at
    the time, not here. What is useful is knowing which policies are on, and
    which of them name this identity or the applications being diagnosed.
    """
    rows = safely(
        lambda: get_collection(session, config, "conditional_access_policies"),
        notes,
        "Conditional access policies",
        (),
        needed_for(config, "conditional_access"),
    )
    policies = [
        {
            "display_name": text(row.get("displayName")),
            "state": text(row.get("state")),
            "applications": _targets(row, "applications"),
            "users": _targets(row, "users"),
        }
        for row in rows
    ]
    enabled = [item for item in policies if item["state"] == "enabled"]
    return {
        "policy_count": len(policies),
        "enabled_count": len(enabled),
        "policies": policies,
        "note": (
            "Whether a policy applies to a sign in is decided at the time. The "
            "sign in log entry names the policies that were evaluated."
            if policies
            else "No policies were readable. This needs Policy.Read.All."
        ),
    }


def _targets(policy: Mapping[str, Any], key: str) -> dict[str, Any]:
    """Return the include and exclude lists of one condition."""
    conditions = policy.get("conditions")
    if not isinstance(conditions, Mapping):
        return {}
    section = conditions.get(key)
    if not isinstance(section, Mapping):
        return {}
    return {
        name: value
        for name, value in section.items()
        if name.startswith(("include", "exclude")) and value
    }


def whoami(
    session: Session,
    config: Config,
    credential: TokenCredential,
    context: AuthContext,
    *,
    with_policies: bool = True,
) -> dict[str, Any]:
    """Report the identity in use and everything that bounds it."""
    notes: list[str] = []
    token = token_provider(credential, config.endpoints.graph.scope)()
    claims = decode_claims(token)
    tenant = tenant_details(session, config, notes)

    identity: dict[str, Any]
    if context.identity_kind == "delegated":
        identity = signed_in_user(session, config, notes)
    else:
        app_id = context.client_id or text(claims.get("appid") or claims.get("azp"))
        identity = service_principal_identity(session, config, app_id, notes)

    report: dict[str, Any] = {
        "authentication": {
            "source": context.source,
            "identity_kind": context.identity_kind,
            "description": context.description,
        },
        "tenant": tenant or {"tenant_id": text(claims.get("tid"))},
        "identity": identity,
        "token": {
            name: text(claims.get(name))
            for name in CLAIMS_OF_INTEREST
            if claims.get(name)
        },
        "permissions": {
            "application_permissions": list(claim_values(claims, "roles")),
            "delegated_scopes": list(claim_values(claims, "scp")),
            "directory_role_template_ids_in_token": list(claim_values(claims, "wids")),
        },
        "reachable_tenants": reachable_tenants(config, credential, notes),
    }
    if with_policies:
        report["conditional_access"] = conditional_access(session, config, notes)
    if notes:
        report["not_readable"] = notes
    return report


def graph_session_for(config: Config, credential: TokenCredential) -> Session:
    """Build a session carrying a Microsoft Graph token."""
    return build_session(config, graph_token_provider(config, credential))
