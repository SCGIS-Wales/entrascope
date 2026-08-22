"""Preflight checks.

``entrascope doctor`` answers one question: why did that not work. It checks the
credential file, the network path, token acquisition, what the token actually
grants, the licence tier, and which diagnostic settings are exporting logs.

Every check returns the same result object, and every failure carries
remediation and a documentation link. Nothing here ever prints a secret.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from azure.core.credentials import TokenCredential

from entrascope.capabilities import (
    ROLES_CLAIM,
    SCOPES_CLAIM,
    capability_results,
    claim_values,
    decode_claims,
    grant_command,
    licence_tier,
    missing_permissions,
    missing_scopes,
    permissions_docs_url,
    read_diagnostic_settings,
    required_permissions,
    sufficient_directory_roles,
)
from entrascope.config import Config
from entrascope.credentials import check_permissions, resolve_auth
from entrascope.graph import get_collection, graph_token_provider, token_provider
from entrascope.http import Session, build_session, network_trust
from entrascope.logger import get_logger
from entrascope.models import (
    ApiCallError,
    AuthContext,
    AuthSource,
    CheckResult,
    CredentialError,
)

log = get_logger(__name__)


def check_network(config: Config) -> CheckResult:
    """Report the forward proxy and certificate trust in force.

    This is a report rather than a judgement. An engineer behind a corporate
    proxy needs to see what entrascope is actually using before anything else
    makes sense.
    """
    trust = network_trust(config)
    return CheckResult(
        check="network path",
        passed=trust.verify_enabled,
        detail=trust.summary(),
        remediation=(
            ""
            if trust.verify_enabled
            else "Certificate verification is disabled in configuration. Set "
            "verify_tls back to true and name your certificate authority "
            "bundle in one of the configured variables instead."
        ),
    )


def check_credential_storage(
    config: Config, source: AuthSource | None
) -> tuple[CheckResult, ...]:
    """Check the credential file, unless the active source does not use one."""
    if source is not None and source != "file":
        return (
            CheckResult(
                check="credential storage",
                passed=True,
                detail=f"Not applicable. The {source} source uses no credential file.",
            ),
        )
    return check_permissions(config.credentials)


def check_token(
    config: Config, credential: TokenCredential, context: AuthContext
) -> tuple[CheckResult, str]:
    """Acquire a token and report whether the authority accepted us."""
    try:
        token = token_provider(credential, config.endpoints.graph.scope)()
    except Exception as error:
        return (
            CheckResult(
                check="token acquisition",
                passed=False,
                detail=(
                    "The authority refused to issue a token using "
                    f"{context.description}."
                ),
                remediation=str(error).splitlines()[0] if str(error) else "",
                docs_url=config.error_codes.defaults.docs_url,
            ),
            "",
        )
    return (
        CheckResult(
            check="token acquisition",
            passed=True,
            detail=f"Acquired a token using {context.description}.",
        ),
        token,
    )


def check_authorisation(
    config: Config, claims: Mapping[str, Any], context: AuthContext
) -> tuple[CheckResult, tuple[str, ...]]:
    """Check what the token actually grants, read from the token itself.

    An application token carries roles. A delegated token, such as the one an
    Azure CLI session yields, carries scopes, and the directory roles the
    signed in person holds decide what those scopes can read. The two are
    checked differently and the remediation differs accordingly.
    """
    if context.identity_kind == "delegated":
        held = claim_values(claims, SCOPES_CLAIM)
        missing = missing_scopes(claims, config)
        roles = ", ".join(sufficient_directory_roles(config))
        return (
            CheckResult(
                check="authorisation",
                passed=not missing,
                detail=(
                    f"Delegated token carrying {len(held)} scopes."
                    if not missing
                    else f"Delegated token is missing {', '.join(missing)}."
                ),
                remediation=(
                    ""
                    if not missing
                    else f"Ask for one of these directory roles: {roles}. A "
                    "delegated session is limited by the directory roles the "
                    "signed in person holds."
                ),
                docs_url="" if not missing else permissions_docs_url(config),
            ),
            held,
        )

    held = claim_values(claims, ROLES_CLAIM)
    absent = missing_permissions(claims, config)
    wanted = ", ".join(permission.name for permission in required_permissions(config))
    return (
        CheckResult(
            check="authorisation",
            passed=not absent,
            detail=(
                f"Token carries {', '.join(held)}."
                if not absent
                else "Token is missing "
                + ", ".join(permission.name for permission in absent)
                + f". Required: {wanted}."
            ),
            remediation=(
                ""
                if not absent
                else grant_command(absent, config, context.client_id or "<client-id>")
            ),
            docs_url="" if not absent else permissions_docs_url(config),
        ),
        held,
    )


def check_licence(
    config: Config, skus: Sequence[Mapping[str, Any]]
) -> tuple[CheckResult, str]:
    """Report the observed licence tier."""
    tier = licence_tier(skus, config)
    free = config.capabilities.licences.free_label
    return (
        CheckResult(
            check="licence tier",
            passed=True,
            detail=(
                f"The tenant reports {tier}."
                + (
                    " Sign in log export and Microsoft Graph activity need P1 or P2."
                    if tier == free
                    else ""
                )
            ),
        ),
        tier,
    )


def check_diagnostics(
    config: Config, categories: Sequence[str], error: str = ""
) -> tuple[CheckResult, ...]:
    """Check each diagnostic category, naming what is missing and how to enable it."""
    if error:
        return (
            CheckResult(
                check="diagnostic settings",
                passed=False,
                detail=f"Could not read the diagnostic settings. {error}",
                remediation=(
                    "Reading diagnostic settings needs an Azure Resource Manager "
                    "token and the Security Administrator role."
                ),
            ),
        )
    enabled = set(categories)
    results: list[CheckResult] = []
    for entry in config.tables.diagnostic_categories:
        present = entry.name in enabled
        capability = next(
            (
                item
                for item in config.capabilities.capabilities
                if item.requires.diagnostic_category == entry.name
            ),
            None,
        )
        results.append(
            CheckResult(
                check=f"diagnostic category {entry.name}",
                passed=present,
                detail=(
                    f"Exported to a workspace. Table {entry.table}."
                    if present
                    else f"Not exported. {entry.description} "
                    f"Needs {entry.minimum_licence} or better."
                ),
                remediation=(
                    "" if present or capability is None else capability.remediation
                ),
                docs_url="" if present or capability is None else capability.docs_url,
            )
        )
    return tuple(results)


def gather(
    config: Config,
    session: Session,
) -> tuple[tuple[Mapping[str, Any], ...], tuple[str, ...], str]:
    """Read the subscribed licences and the diagnostic settings.

    Either call may fail on a tenant that has not granted everything, and a
    failure in one must not stop the other, because a partial report is still
    useful.
    """
    skus: tuple[Mapping[str, Any], ...] = ()
    categories: tuple[str, ...] = ()
    error = ""
    try:
        skus = get_collection(session, config, "subscribed_skus")
    except ApiCallError as failure:
        log.debug("could not read the subscribed licences: %s", failure.error.summary())
    try:
        categories = read_diagnostic_settings(session, config)
    except ApiCallError as failure:
        error = failure.error.summary()
    return skus, categories, error


def run_checks(
    config: Config,
    *,
    requested: AuthSource | None = None,
    session: Session | None = None,
) -> tuple[CheckResult, ...]:
    """Run every preflight check and return the results in report order."""
    results: list[CheckResult] = [check_network(config)]
    results.extend(check_credential_storage(config, requested))

    try:
        context, credential = resolve_auth(config, requested)
    except CredentialError as failure:
        results.append(
            CheckResult(
                check="authentication",
                passed=False,
                detail=str(failure).splitlines()[0],
                remediation="Run az login and pass --auth azure-cli, or place "
                "client credentials in the credential file.",
            )
        )
        return tuple(results)

    results.append(
        CheckResult(
            check="authentication source",
            passed=True,
            detail=f"Using {context.description}.",
        )
    )

    token_result, token = check_token(config, credential, context)
    results.append(token_result)
    if not token:
        return tuple(results)

    claims = decode_claims(token)
    authorisation, held = check_authorisation(config, claims, context)
    results.append(authorisation)

    owned = session is None
    active = session or build_session(config, graph_token_provider(config, credential))
    try:
        skus, categories, diagnostics_error = gather(config, active)
    finally:
        if owned:
            active.close()

    licence, tier = check_licence(config, skus)
    results.append(licence)
    results.extend(check_diagnostics(config, categories, diagnostics_error))
    results.extend(
        capability_results(
            config, tier=tier, categories=categories, held_permissions=held
        )
    )
    return tuple(results)
