"""The MCP tool surface, shared by the local and remote servers.

Every tool calls the same free functions the command line calls and returns the
payload :mod:`entrascope.render` produces, so an MCP result and a CLI
``--output json`` payload are the same bytes. A test asserts it.

Tools read. There is no tool that changes the directory.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from typing import Any, cast

from azure.core.credentials import TokenCredential
from fastmcp import FastMCP

from entrascope.config import Config, read_text_file
from entrascope.credentials import resolve_auth
from entrascope.discovery import (
    discover_applications,
    discover_service_principals,
    is_first_party,
    narrowed,
)
from entrascope.doctor import run_checks
from entrascope.errors import explain, known_codes, search
from entrascope.graph import graph_token_provider
from entrascope.http import Session, build_session
from entrascope.identity import graph_session_for
from entrascope.identity import whoami as run_whoami
from entrascope.inspect import inspect as run_inspect
from entrascope.inspect import search_gallery
from entrascope.investigate import investigate as run_investigation
from entrascope.investigate import matches, matches_principal
from entrascope.logger import get_logger, new_correlation_id
from entrascope.logs import (
    audit_categories,
    query_audit_graph,
    query_graph_activity,
    query_sign_ins_graph,
    query_sign_ins_monitor,
    sign_in_kinds,
)
from entrascope.models import AuthSource, ConfigError, Severity
from entrascope.monitor import build_logs_client
from entrascope.render import payload_for

log = get_logger(__name__)

#: Signature of the function each server hands us to obtain an identity.
CredentialFactory = Callable[[], TokenCredential]

#: Name every server registers under.
SERVER_NAME = "entrascope"

#: Shown to a client so it knows what this server is for.
INSTRUCTIONS = """
entrascope gives observability over Microsoft Entra ID and Azure Monitor so
that an application authentication or authorisation failure can be diagnosed.

Start with the doctor tool when something is not working. It reports the
network path, the identity in use, what the token actually grants, the licence
tier and which diagnostic categories are exporting logs, each failure with its
remediation.

Entra directory operations do not appear in the Azure subscription activity
log. They are recorded in the Entra audit logs, which the audit_events tool
reads.

Every tool reads. None of them changes the directory.
""".strip()


def credential_factory(
    config: Config, requested: AuthSource | None = None
) -> CredentialFactory:
    """Return a function that resolves an identity, doing so at most once."""
    cache: dict[str, TokenCredential] = {}

    def provide() -> TokenCredential:
        if "credential" not in cache:
            _, credential = resolve_auth(config, requested)
            cache["credential"] = credential
        return cache["credential"]

    return provide


def graph_session(
    config: Config, credential: TokenCredential
) -> tuple[Session, Callable[[], str]]:
    """Build a session carrying a Microsoft Graph token, and the provider itself.

    The provider is returned separately because the fan out builds its own
    sessions, and a requests auth callable is not a token provider.
    """
    token = graph_token_provider(config, credential)
    return build_session(config, token), token


@contextmanager
def open_graph(
    config: Config, credential: TokenCredential
) -> Iterator[tuple[Session, Callable[[], str]]]:
    """Yield a Graph session and close it afterwards.

    Every tool that reads from Graph opens one and has to remember to close it.
    Eight repetitions of the same try and finally is eight chances to forget,
    and a session left open in a long lived server holds its connection pool
    until the process ends.
    """
    session, token = graph_session(config, credential)
    try:
        yield session, token
    finally:
        session.close()


def payload(rows: Any, config: Config) -> Any:
    """Return the structured content for a tool result."""
    return payload_for(rows, config)


def register_tools(
    server: FastMCP,
    config: Config,
    credential: CredentialFactory,
    requested: AuthSource | None = None,
) -> FastMCP:
    """Register every tool on a server.

    The server object comes from FastMCP and the tools are closures over the
    configuration and the identity, so no state is held at module level.
    """

    @server.tool(
        name="doctor",
        description=(
            "Check everything entrascope needs and explain whatever is missing: "
            "the network path, the credential storage, the identity in use, what "
            "the token grants, the licence tier and every diagnostic category."
        ),
    )
    def doctor() -> list[dict[str, Any]]:
        new_correlation_id()
        return list(payload(run_checks(config), config))

    @server.tool(
        name="investigate",
        description=(
            "Diagnose authentication and authorisation failures, ranked worst "
            "first. With no target this sweeps the whole tenant. Give an "
            "application id, an object id or part of a display name to narrow "
            "it to one application. Start here when something is wrong."
        ),
    )
    def investigate_tool(
        target: str = "",
        severity: str | None = None,
        limit: int = 100,
        kinds: list[str] | None = None,
        include_first_party: bool = False,
    ) -> dict[str, Any]:
        new_correlation_id()
        with open_graph(config, credential()) as (session, token):
            result = run_investigation(
                session,
                config,
                token,
                target=target,
                limit=limit,
                kinds=kinds or None,
                minimum_severity=cast("Severity | None", severity),
                include_first_party=include_first_party,
            )
        return dict(payload(result, config))

    @server.tool(
        name="configuration",
        description=(
            "Read the configuration this tool runs on: where it is being read "
            "from, and the contents of one file. Every endpoint, table name, "
            "error code and vocabulary lives there, so this is how to find out "
            "what the tool knows."
        ),
    )
    def configuration(name: str = "") -> dict[str, Any]:
        if not name:
            return {
                "directory": str(config.root),
                "files": sorted(item.name for item in config.root.glob("*.yaml")),
                "kql_templates": sorted(
                    item.stem for item in (config.root / "kql").glob("*.kql")
                ),
            }
        path = (config.root / name).resolve()
        if not path.is_relative_to(config.root.resolve()) or not path.is_file():
            raise ConfigError(
                f"No configuration file named {name}. Ask with no name for the list."
            )
        return {"name": name, "contents": read_text_file(path)}

    @server.tool(
        name="whoami",
        description=(
            "Show which tenant and identity entrascope is querying as, the "
            "tenants it can reach, the permissions the token actually carries, "
            "the directory roles held, the administrative units that bound "
            "them, and the conditional access policies in force. Start here "
            "when a result is not what was expected."
        ),
    )
    def whoami_tool(with_policies: bool = True) -> dict[str, Any]:
        new_correlation_id()
        auth_context, azure_credential = resolve_auth(config, requested)
        session = graph_session_for(config, azure_credential)
        try:
            return dict(
                payload(
                    run_whoami(
                        session,
                        config,
                        azure_credential,
                        auth_context,
                        with_policies=with_policies,
                    ),
                    config,
                )
            )
        finally:
            session.close()

    @server.tool(
        name="inspect",
        description=(
            "Show everything about one application: the registration and the "
            "enterprise application together, the scopes it exposes, the roles "
            "it defines, what it asked for against what was consented, every "
            "URL it is registered with, its credentials and their expiry, and "
            "its single sign on configuration. Give part of a display name, an "
            "application id or an object id."
        ),
    )
    def inspect_tool(
        target: str, application_type: str | None = None
    ) -> dict[str, Any]:
        new_correlation_id()
        with open_graph(config, credential()) as (session, token):
            report = run_inspect(
                session,
                config,
                token,
                target=target,
                kinds=[application_type] if application_type else [],
            )
        return dict(payload(report, config))

    @server.tool(
        name="gallery_applications",
        description=(
            "Search the gallery of applications that can be added to the "
            "tenant, which answers whether something is available ready made "
            "and which single sign on modes it supports."
        ),
    )
    def gallery_applications(term: str = "", limit: int = 50) -> dict[str, Any]:
        """Search the gallery, saying when the answer is only a near match.

        The gallery endpoint filters on a case sensitive prefix, so a search
        often answers with what starts the same rather than with what was
        asked for. The command says so. Returning the rows alone left an
        assistant presenting near matches as though they were the answer, so
        the note comes back with them.
        """
        new_correlation_id()
        with open_graph(config, credential()) as (session, _token):
            rows, note = search_gallery(session, config, term, limit)
        return {
            "applications": [
                {
                    "display_name": row.get("displayName"),
                    "publisher": row.get("publisher"),
                    "categories": row.get("categories"),
                    "single_sign_on_modes": row.get("supportedSingleSignOnModes"),
                    "id": row.get("id"),
                }
                for row in rows
            ],
            "note": note,
            "exact": not note,
        }

    @server.tool(
        name="discover_applications",
        description=(
            "List application registrations with sign in audience, redirect URIs, "
            "requested permissions, owners, credentials and their expiry, and "
            "federated identity credentials."
        ),
    )
    def discover_applications_tool(
        app: str = "",
        filter_expression: str | None = None,
        application_type: str | None = None,
        expiring_only: bool = False,
        with_details: bool = True,
    ) -> list[dict[str, Any]]:
        new_correlation_id()
        with open_graph(config, credential()) as (session, token):
            rows = discover_applications(
                session,
                config,
                token if with_details else None,
                filter_expression=filter_expression,
                with_details=with_details,
            )
        found = narrowed(rows, app, application_type, matches)
        if expiring_only:
            found = tuple(row for row in found if row.expiring())
        return list(payload(found, config))

    @server.tool(
        name="discover_service_principals",
        description=(
            "List enterprise applications, including managed identities and SAML "
            "applications, with their assignment requirement and granted "
            "permissions."
        ),
    )
    def discover_service_principals_tool(
        app: str = "",
        filter_expression: str | None = None,
        application_type: str | None = None,
        include_first_party: bool = False,
        with_details: bool = True,
    ) -> list[dict[str, Any]]:
        new_correlation_id()
        with open_graph(config, credential()) as (session, token):
            rows = discover_service_principals(
                session,
                config,
                token if with_details else None,
                filter_expression=filter_expression,
                with_details=with_details,
            )
        if not include_first_party:
            rows = tuple(row for row in rows if not is_first_party(row, config))
        return list(
            payload(narrowed(rows, app, application_type, matches_principal), config)
        )

    default_category = config.tables.default_audit_category
    known_categories = ", ".join(audit_categories(config))
    activity = config.tables.log_queries["graph-activity"]

    @server.tool(
        name="audit_events",
        description=(
            "Read Entra directory changes. Defaults to the "
            f"{default_category} category, which is where changes to "
            "application registrations and enterprise applications are "
            f"recorded. Categories: {known_categories}. These do not appear in "
            "the Azure subscription activity log."
        ),
    )
    def audit_events(
        category: str | None = None,
        target: str = "",
        failures_only: bool = False,
        lookback_hours: int | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        new_correlation_id()
        with open_graph(config, credential()) as (session, _token):
            rows = query_audit_graph(
                session,
                config,
                category=category,
                target=target,
                lookback_hours=lookback_hours,
                top=limit,
            )
        if failures_only:
            failures = set(config.fields.findings.audit_failure_results)
            rows = tuple(row for row in rows if row.result.lower() in failures)
        return list(payload(rows, config))

    @server.tool(
        name="audit_categories",
        description=(
            "List the directory audit categories that can be read, and which "
            "one audit_events reads when none is named."
        ),
    )
    def audit_categories_tool() -> list[dict[str, Any]]:
        return [
            {
                "category": name,
                "graph_value": value or "every category",
                "default": name == default_category,
            }
            for name, value in sorted(config.tables.audit_categories.items())
        ]

    @server.tool(
        name="sign_ins",
        description=(
            "Read sign ins of one kind. Use service-principal to see client "
            "credentials failures, which is what most application authentication "
            "problems look like."
        ),
    )
    def sign_ins(
        kind: str = "interactive",
        app_id: str | None = None,
        failures_only: bool = False,
        limit: int | None = None,
        workspace_id: str | None = None,
        lookback_hours: int | None = None,
    ) -> list[dict[str, Any]]:
        new_correlation_id()
        if workspace_id:
            client = build_logs_client(credential(), config)
            return list(
                payload(
                    query_sign_ins_monitor(
                        client,
                        config,
                        workspace_id,
                        kind=kind,
                        app_id=app_id or "",
                        failures_only=failures_only,
                        lookback_hours=lookback_hours,
                        row_limit=limit,
                    ),
                    config,
                )
            )
        with open_graph(config, credential()) as (session, _token):
            rows = query_sign_ins_graph(
                session,
                config,
                kind=kind,
                app_id=app_id,
                failures_only=failures_only,
                lookback_hours=lookback_hours,
                top=limit,
            )
        return list(payload(rows, config))

    @server.tool(
        name="graph_activity",
        description=(
            "Read Microsoft Graph requests made against the tenant. Available "
            f"only through Azure Monitor, and needs the "
            f"{activity.diagnostic_category} diagnostic category and an Entra ID "
            "P1 or P2 licence."
        ),
    )
    def graph_activity(
        workspace_id: str,
        app_id: str = "",
        lookback_hours: int | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        new_correlation_id()
        client = build_logs_client(credential(), config)
        rows = query_graph_activity(
            client,
            config,
            workspace_id,
            app_id=app_id,
            lookback_hours=lookback_hours,
            row_limit=limit,
        )
        return list(payload(rows, config))

    @server.tool(
        name="explain_error",
        description=(
            "Explain an AADSTS or Microsoft Graph error code, or a message "
            "carrying one, with its likely cause, remediation and documentation. "
            "Needs no credentials."
        ),
    )
    def explain_error(code: str) -> dict[str, Any]:
        result = payload(explain(code, config), config)
        return dict(result)

    @server.tool(
        name="list_error_codes",
        description=(
            "List every error code entrascope can explain, optionally filtered by "
            "a search term matching the code or its meaning."
        ),
    )
    def list_error_codes(term: str | None = None) -> list[dict[str, Any]]:
        rows = (
            list(search(term, config))
            if term
            else [explain(code, config) for code in known_codes(config)]
        )
        return list(payload(rows, config))

    @server.tool(
        name="sign_in_kinds",
        description="List the sign in kinds the sign_ins tool accepts.",
    )
    def sign_in_kinds_tool() -> list[str]:
        return list(sign_in_kinds(config))

    return server


#: Which tool answers which command, so that the two surfaces cannot drift
#: apart in what they can do. A test walks the command line and checks that
#: every command below serve appears here.
COMMAND_TOOLS: dict[str, str] = {
    "doctor": "doctor",
    "investigate": "investigate",
    "whoami": "whoami",
    "inspect app": "inspect",
    "inspect applications": "discover_applications",
    "inspect enterprise-apps": "discover_service_principals",
    "inspect gallery": "gallery_applications",
    "logs audit": "audit_events",
    "logs signins": "sign_ins",
    "logs graph-activity": "graph_activity",
    "logs kinds": "sign_in_kinds",
    "logs categories": "audit_categories",
    "errors explain": "explain_error",
    "errors list": "list_error_codes",
    "errors search": "list_error_codes",
    "config path": "configuration",
    "config show": "configuration",
}

#: Commands deliberately absent from the tool surface, and why. An assistant
#: should not be writing to somebody's disk on its own initiative, and there is
#: nothing it could learn by doing so that the configuration tool cannot tell
#: it by reading.
NOT_EXPOSED: dict[str, str] = {
    "upgrade": (
        "Installs software on the machine. Upgrading is a decision for the "
        "person at the keyboard, not for an assistant."
    ),
    "config export": (
        "Writes files to the machine. An assistant reads the configuration "
        "with the configuration tool instead."
    ),
}


def tool_names() -> tuple[str, ...]:
    """Return the names of every tool, in registration order."""
    return (
        "doctor",
        "investigate",
        "configuration",
        "whoami",
        "inspect",
        "gallery_applications",
        "discover_applications",
        "discover_service_principals",
        "audit_events",
        "audit_categories",
        "sign_ins",
        "graph_activity",
        "explain_error",
        "list_error_codes",
        "sign_in_kinds",
    )


def validate_kind(kind: str, config: Config) -> Sequence[str]:
    """Return the known sign in kinds, for a caller validating its input."""
    _ = kind
    return sign_in_kinds(config)
