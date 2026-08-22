"""Capability detection.

What entrascope can actually do in a given tenant depends on three things: the
permissions the identity holds, the licence tier, and which diagnostic settings
route logs to a workspace. Every prerequisite and every remediation comes from
``config/capabilities.yaml``, so a new capability needs no code change.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import jwt

from entrascope.config import Capability, Config, GraphPermission
from entrascope.http import Session, get_json
from entrascope.logger import get_logger
from entrascope.models import CheckResult

log = get_logger(__name__)

#: Claim names in an Entra access token.
ROLES_CLAIM = "roles"
SCOPES_CLAIM = "scp"
TENANT_CLAIM = "tid"
AUTHORIZED_PARTY_CLAIM = "azp"

#: Licence tiers, most capable first.
TIER_P2 = "P2"
TIER_P1 = "P1"


def decode_claims(token: str) -> dict[str, Any]:
    """Read the claims of an access token without verifying it.

    The token was just issued to us by the authority over TLS, so there is
    nothing to verify here. This reads what the tenant actually granted, which
    is more trustworthy than any table of expected permissions.
    """
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as error:
        log.debug("could not read the access token claims: %s", error)
        return {}
    return dict(claims) if isinstance(claims, Mapping) else {}


def claim_values(claims: Mapping[str, Any], name: str) -> tuple[str, ...]:
    """Return a claim as a tuple, whether it arrived as a list or a string."""
    value = claims.get(name)
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part for part in value.split() if part)
    if isinstance(value, Sequence):
        return tuple(str(item) for item in value)
    return (str(value),)


def required_permissions(config: Config) -> tuple[GraphPermission, ...]:
    """Return the Graph permissions entrascope needs."""
    return tuple(
        permission
        for permission in config.capabilities.graph_permissions
        if permission.required
    )


def missing_permissions(
    claims: Mapping[str, Any], config: Config
) -> tuple[GraphPermission, ...]:
    """Return the required permissions absent from an application token."""
    held = {value.lower() for value in claim_values(claims, ROLES_CLAIM)}
    return tuple(
        permission
        for permission in required_permissions(config)
        if permission.name.lower() not in held
    )


def missing_scopes(claims: Mapping[str, Any], config: Config) -> tuple[str, ...]:
    """Return the required permissions absent from a delegated token.

    A delegated token carries scopes, and the directory roles the signed in
    person holds decide what those scopes can actually read.
    """
    held = {value.lower() for value in claim_values(claims, SCOPES_CLAIM)}
    return tuple(
        permission.name
        for permission in required_permissions(config)
        if permission.name.lower() not in held
    )


def sufficient_directory_roles(config: Config) -> tuple[str, ...]:
    """Return the directory roles that cover the read surface on their own."""
    return tuple(
        role.name
        for role in config.capabilities.directory_roles
        if role.sufficient is True
    )


def grant_command(
    missing: Sequence[GraphPermission], config: Config, client_id: str = "<client-id>"
) -> str:
    """Return the exact command that grants the missing permissions."""
    if not missing:
        return ""
    graph = config.endpoints.graph.resource_app_id
    roles = " \\\n  ".join(f"{permission.app_role_id}=Role" for permission in missing)
    return (
        f"az ad app permission add --id {client_id} --api {graph} \\\n"
        f"  --api-permissions \\\n  {roles}\n"
        f"az ad app permission admin-consent --id {client_id}"
    )


def permissions_docs_url(config: Config) -> str:
    """Return the documentation link for granting Graph permissions."""
    for capability in config.capabilities.capabilities:
        if capability.requires.graph_permission:
            return capability.docs_url
    return config.error_codes.defaults.docs_url


def licence_tier(skus: Sequence[Mapping[str, Any]], config: Config) -> str:
    """Determine the Entra ID tier from the subscribed service plans.

    Reported as observed rather than asserted as entitlement, because licence
    gating is tenant specific and some tenants report a tier they cannot use.
    """
    licences = config.capabilities.licences
    plans: set[str] = set()
    for sku in skus:
        for plan in sku.get("servicePlans", []) or []:
            if isinstance(plan, Mapping):
                name = str(plan.get("servicePlanName", ""))
                if name:
                    plans.add(name)
    if plans & set(licences.p2_service_plans):
        return TIER_P2
    if plans & set(licences.p1_service_plans):
        return TIER_P1
    return licences.free_label


def tier_satisfies(tier: str, required: str | None, config: Config) -> bool:
    """Return whether an observed tier meets a required one."""
    if not required or required == config.capabilities.licences.free_label:
        return True
    order = {config.capabilities.licences.free_label: 0, TIER_P1: 1, TIER_P2: 2}
    return order.get(tier, 0) >= order.get(required, 0)


def diagnostic_settings_url(config: Config) -> str:
    """Return the Azure Resource Manager URL for the Entra diagnostic settings."""
    azure = config.endpoints.azure
    path = azure.paths["diagnostic_settings"]
    return (
        f"{azure.arm_base_url}{path}"
        f"?api-version={azure.diagnostic_settings_api_version}"
    )


def enabled_categories(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """Return every log category enabled by any diagnostic setting."""
    enabled: set[str] = set()
    for setting in payload.get("value", []) or []:
        if not isinstance(setting, Mapping):
            continue
        properties = setting.get("properties")
        if not isinstance(properties, Mapping):
            continue
        for entry in properties.get("logs", []) or []:
            if isinstance(entry, Mapping) and entry.get("enabled"):
                category = str(entry.get("category", ""))
                if category:
                    enabled.add(category)
    return tuple(sorted(enabled))


def read_diagnostic_settings(session: Session, config: Config) -> tuple[str, ...]:
    """Read the Entra diagnostic settings and return the enabled categories."""
    body = get_json(session, diagnostic_settings_url(config), config, source="arm")
    return enabled_categories(body)


def capability_results(
    config: Config,
    *,
    tier: str,
    categories: Sequence[str],
    held_permissions: Sequence[str],
) -> tuple[CheckResult, ...]:
    """Check every configured capability against what the tenant provides."""
    return tuple(
        capability_result(capability, config, tier, categories, held_permissions)
        for capability in config.capabilities.capabilities
    )


def capability_result(
    capability: Capability,
    config: Config,
    tier: str,
    categories: Sequence[str],
    held_permissions: Sequence[str],
) -> CheckResult:
    """Check one capability against what the tenant provides."""
    requires = capability.requires
    reasons: list[str] = []
    if requires.diagnostic_category and requires.diagnostic_category not in categories:
        reasons.append(f"the {requires.diagnostic_category} category is not exported")
    if not tier_satisfies(tier, requires.licence, config):
        reasons.append(f"the tenant reports {tier} and this needs {requires.licence}")
    if requires.graph_permission:
        held = {value.lower() for value in held_permissions}
        if requires.graph_permission.lower() not in held:
            reasons.append(f"{requires.graph_permission} is not granted")
    if requires.azure_role:
        reasons.append(
            f"needs {requires.azure_role} on the workspace, which cannot be read "
            "from here"
        )
        return CheckResult(
            check=capability.id,
            passed=True,
            detail=f"Assumed available. Requires {requires.azure_role}.",
            remediation=capability.remediation,
            docs_url=capability.docs_url,
        )
    if reasons:
        return CheckResult(
            check=capability.id,
            passed=False,
            detail="Unavailable because " + ", and ".join(reasons) + ".",
            remediation=capability.remediation,
            docs_url=capability.docs_url,
        )
    return CheckResult(
        check=capability.id,
        passed=True,
        detail="Available.",
        docs_url=capability.docs_url,
    )
