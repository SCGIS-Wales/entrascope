"""Command line surface.

The click group is the only public entry point. Every command delegates to a
free function in another module and renders through :mod:`entrascope.render`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from functools import wraps
from pathlib import Path
from typing import Any

import click

from entrascope import __version__
from entrascope.config import Config, load_config
from entrascope.credentials import resolve_auth
from entrascope.discovery import discover_applications, discover_service_principals
from entrascope.doctor import run_checks
from entrascope.errors import explain, explain_api_error, known_codes, search
from entrascope.graph import graph_token_provider
from entrascope.http import Session, build_session
from entrascope.logger import bind_context, configure_logging, new_correlation_id
from entrascope.logs import (
    query_audit_graph,
    query_audit_monitor,
    query_graph_activity,
    query_sign_ins_graph,
    query_sign_ins_monitor,
)
from entrascope.models import (
    AUTH_SOURCE_ORDER,
    ApiCallError,
    AuthSource,
    ConfigError,
    CredentialError,
)
from entrascope.monitor import build_logs_client
from entrascope.render import (
    EXIT_API,
    EXIT_CHECKS_FAILED,
    EXIT_CONFIG,
    EXIT_CREDENTIALS,
    OUTPUT_FORMATS,
    OutputFormat,
    emit,
    emit_error,
    exit_code_for_checks,
    render,
    render_checks,
)

#: Key under which the shared settings are held on the click context.
SETTINGS = "settings"


def log_level(output: str, verbose: bool) -> str | None:
    """Return the log level for one invocation.

    A machine readable format is quiet unless asked otherwise, so that a caller
    piping the output is not reading progress lines it did not ask for.
    """
    if verbose:
        return "DEBUG"
    if output in ("json", "yaml"):
        return "WARNING"
    return None


def build_settings(
    config_dir: Path | None, auth: str | None, output: str, verbose: bool
) -> dict[str, Any]:
    """Load configuration and prepare the shared settings for every command."""
    config = load_config(config_dir)
    configure_logging(config, surface="cli", level=log_level(output, verbose))
    new_correlation_id()
    if auth:
        bind_context(auth_source=auth)
    return {"config": config, "auth": auth, "output": output}


def settings_of(context: click.Context) -> dict[str, Any]:
    """Return the shared settings from the click context.

    The settings are placed on the root context by the group callback, so a
    subcommand and the error handler both find them by walking up.
    """
    current: click.Context | None = context
    while current is not None:
        values = current.obj or {}
        result = values.get(SETTINGS) if isinstance(values, dict) else None
        if isinstance(result, dict):
            return dict(result)
        current = current.parent
    return {}


#: Columns shown in a table. The full projection is always in the JSON form.
APPLICATION_COLUMNS = (
    "display_name",
    "app_id",
    "application_type",
    "audience_label",
    "credentials",
    "owners",
)
SERVICE_PRINCIPAL_COLUMNS = (
    "display_name",
    "app_id",
    "application_type",
    "account_enabled",
    "app_role_assignment_required",
    "owners",
)
AUDIT_COLUMNS = ("timestamp", "activity", "result", "initiated_by", "target")
SIGN_IN_COLUMNS = (
    "timestamp",
    "identity",
    "app_display_name",
    "client_app",
    "error_code",
    "failure_reason",
)
GRAPH_ACTIVITY_COLUMNS = (
    "timestamp",
    "app_id",
    "method",
    "status",
    "uri",
    "duration_ms",
)
EXPLANATION_COLUMNS = ("code", "meaning", "likely_cause", "remediation", "docs_url")

#: Where a log query is answered from.
ROUTES = ("graph", "monitor")


def authenticated_session(
    settings: Mapping[str, Any],
) -> tuple[Config, Session, Callable[[], str]]:
    """Resolve an identity, build a session, and return the token provider too.

    The provider is returned rather than taken back off the session, because
    the session holds a requests auth callable and not a token provider, and
    the two have different signatures.
    """
    config: Config = settings["config"]
    context, credential = resolve_auth(config, settings.get("auth"))
    bind_context(auth_source=context.source, tenant_id=context.tenant_id or "")
    token = graph_token_provider(config, credential)
    return config, build_session(config, token), token


def logs_client(settings: Mapping[str, Any]) -> tuple[Config, Any]:
    """Resolve an identity and build the Log Analytics client."""
    config: Config = settings["config"]
    _, credential = resolve_auth(config, settings.get("auth"))
    return config, build_logs_client(credential, config)


def require_workspace(workspace: str | None) -> str:
    """Return the workspace identifier, or explain that one is needed."""
    if workspace:
        return workspace
    raise ConfigError(
        "The Azure Monitor route needs a Log Analytics workspace. Pass "
        "--workspace with the workspace id, or use --route graph where the "
        "source supports it."
    )


def show(
    rows: Sequence[Any],
    settings: Mapping[str, Any],
    title: str,
    columns: Sequence[str],
) -> None:
    """Render rows in the requested format and write them out."""
    config: Config = settings["config"]
    output: OutputFormat = settings.get("output", "table")
    emit(render(rows, config, output, title=title, columns=columns))


def explanation_for(error: ApiCallError) -> str:
    """Return the remediation for a failed call, or an empty string.

    Explaining the failure is the whole purpose of this tool, so a failure that
    carries a recognised code prints its remediation rather than only its
    status.
    """
    context = click.get_current_context(silent=True)
    settings = settings_of(context) if context is not None else {}
    config = settings.get("config")
    if config is None:
        return ""
    explanation = explain_api_error(error.error, config)
    if not explanation.known:
        return ""
    lines = [f"\n{explanation.code}: {explanation.meaning}"]
    if explanation.likely_cause:
        lines.append(f"Likely cause: {explanation.likely_cause}")
    lines.append(f"Remediation: {explanation.remediation}")
    lines.append(f"See: {explanation.docs_url}")
    return "\n".join(line.strip() for line in lines)


def handled[Returns](function: Callable[..., Returns]) -> Callable[..., Returns]:
    """Turn the deliberate errors into a message and an exit code.

    A stack trace helps nobody diagnose a tenant. Every error entrascope raises
    on purpose already carries its own remediation, so it is printed as it is.
    """

    @wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Returns:
        try:
            return function(*args, **kwargs)
        except ConfigError as error:
            emit_error(str(error))
            raise SystemExit(EXIT_CONFIG) from error
        except CredentialError as error:
            emit_error(str(error))
            raise SystemExit(EXIT_CREDENTIALS) from error
        except ApiCallError as error:
            emit_error(error.error.summary())
            emit_error(explanation_for(error))
            raise SystemExit(EXIT_API) from error

    return wrapper


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="entrascope")
@click.option(
    "--auth",
    type=click.Choice(AUTH_SOURCE_ORDER),
    default=None,
    help="Authentication source to use. Naming one selects it whether or not it "
    "is enabled for automatic resolution, so az login and azure-cli need no "
    "configuration change.",
)
@click.option(
    "--output",
    type=click.Choice(OUTPUT_FORMATS),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--config-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Directory holding the configuration files.",
)
@click.option("--verbose", is_flag=True, help="Log at debug level.")
@click.pass_context
@handled
def cli(
    context: click.Context,
    auth: str | None,
    output: str,
    config_dir: Path | None,
    verbose: bool,
) -> None:
    """Diagnose Entra ID and Azure application authentication failures.

    Entra directory operations do not appear in the Azure subscription activity
    log. They are recorded in the Entra audit logs, which this tool reads
    through Microsoft Graph and through Azure Monitor.
    """
    context.ensure_object(dict)
    context.obj[SETTINGS] = build_settings(config_dir, auth, output, verbose)


@cli.command()
@click.pass_context
@handled
def doctor(context: click.Context) -> None:
    """Check everything entrascope needs, and explain whatever is missing.

    Reports the network path, the credential file, the identity in use, what
    the token actually grants, the licence tier and every diagnostic category,
    each failure with its remediation and a documentation link.
    """
    settings = settings_of(context)
    config: Config = settings["config"]
    auth: AuthSource | None = settings.get("auth")
    output: OutputFormat = settings.get("output", "table")
    results = run_checks(config, requested=auth)
    emit(render_checks(results, config, output))
    raise SystemExit(exit_code_for_checks(results))


@cli.group()
def discover() -> None:
    """Enumerate application registrations and enterprise applications."""


@discover.command("apps")
@click.option(
    "--filter", "filter_expression", default=None, help="OData filter to apply."
)
@click.option(
    "--type",
    "application_type",
    default=None,
    help="Show only one application type.",
)
@click.option(
    "--expiring",
    is_flag=True,
    help="Show only applications with a credential expiring or already expired.",
)
@click.option(
    "--no-details",
    is_flag=True,
    help="Skip owners and federated credentials, which need one call per application.",
)
@click.pass_context
@handled
def discover_apps(
    context: click.Context,
    filter_expression: str | None,
    application_type: str | None,
    expiring: bool,
    no_details: bool,
) -> None:
    """List application registrations with the attributes that explain a failure."""
    settings = settings_of(context)
    config, session, token = authenticated_session(settings)
    try:
        rows = discover_applications(
            session,
            config,
            None if no_details else token,
            filter_expression=filter_expression,
            with_details=not no_details,
        )
    finally:
        session.close()
    if application_type:
        rows = tuple(row for row in rows if row.application_type == application_type)
    if expiring:
        rows = tuple(row for row in rows if row.expiring())
    show(rows, settings, "Application registrations", APPLICATION_COLUMNS)


@discover.command("sps")
@click.option(
    "--filter", "filter_expression", default=None, help="OData filter to apply."
)
@click.option(
    "--type",
    "application_type",
    default=None,
    help="Show only one application type.",
)
@click.option(
    "--no-details",
    is_flag=True,
    help="Skip owners and role assignments, which need one call per application.",
)
@click.pass_context
@handled
def discover_service_principals_command(
    context: click.Context,
    filter_expression: str | None,
    application_type: str | None,
    no_details: bool,
) -> None:
    """List enterprise applications, managed identities and SAML applications."""
    settings = settings_of(context)
    config, session, token = authenticated_session(settings)
    try:
        rows = discover_service_principals(
            session,
            config,
            None if no_details else token,
            filter_expression=filter_expression,
            with_details=not no_details,
        )
    finally:
        session.close()
    if application_type:
        rows = tuple(row for row in rows if row.application_type == application_type)
    show(rows, settings, "Enterprise applications", SERVICE_PRINCIPAL_COLUMNS)


@cli.group()
def logs() -> None:
    """Interrogate Entra and Azure Monitor logs.

    Entra directory operations do not appear in the Azure subscription activity
    log. They are in the Entra audit logs, which is what these commands read.
    """


@logs.command("audit")
@click.option("--route", type=click.Choice(ROUTES), default="graph", show_default=True)
@click.option(
    "--workspace",
    default=None,
    help="Log Analytics workspace id, for the monitor route.",
)
@click.option("--hours", type=int, default=None, help="How far back to look.")
@click.option("--limit", type=int, default=None, help="Maximum rows to return.")
@click.option(
    "--target", default="", help="Show only events touching this application."
)
@click.pass_context
@handled
def logs_audit(
    context: click.Context,
    route: str,
    workspace: str | None,
    hours: int | None,
    limit: int | None,
    target: str,
) -> None:
    """Read directory changes to applications, the ApplicationManagement category."""
    settings = settings_of(context)
    if route == "monitor":
        config, client = logs_client(settings)
        rows = query_audit_monitor(
            client,
            config,
            require_workspace(workspace),
            target=target,
            lookback_hours=hours,
            row_limit=limit,
        )
    else:
        config, session, _ = authenticated_session(settings)
        try:
            rows = query_audit_graph(session, config, top=limit)
        finally:
            session.close()
        if target:
            rows = tuple(row for row in rows if target.lower() in row.target.lower())
    show(rows, settings, "Application management audit events", AUDIT_COLUMNS)


@logs.command("signins")
@click.option("--kind", default="interactive", help="Which sign in kind to read.")
@click.option("--route", type=click.Choice(ROUTES), default="graph", show_default=True)
@click.option(
    "--workspace",
    default=None,
    help="Log Analytics workspace id, for the monitor route.",
)
@click.option(
    "--app", "app_id", default="", help="Show only sign ins for this application id."
)
@click.option("--failures-only", is_flag=True, help="Show only sign ins that failed.")
@click.option("--hours", type=int, default=None, help="How far back to look.")
@click.option("--limit", type=int, default=None, help="Maximum rows to return.")
@click.pass_context
@handled
def logs_signins(
    context: click.Context,
    kind: str,
    route: str,
    workspace: str | None,
    app_id: str,
    failures_only: bool,
    hours: int | None,
    limit: int | None,
) -> None:
    """Read sign ins of one kind, interactive by default.

    Service principal sign ins are where client credentials failures appear,
    which is what most application authentication problems look like.
    """
    settings = settings_of(context)
    if route == "monitor":
        config, client = logs_client(settings)
        rows = query_sign_ins_monitor(
            client,
            config,
            require_workspace(workspace),
            kind=kind,
            app_id=app_id,
            lookback_hours=hours,
            row_limit=limit,
        )
        if failures_only:
            rows = tuple(row for row in rows if row.failed())
    else:
        config, session, _ = authenticated_session(settings)
        try:
            rows = query_sign_ins_graph(
                session,
                config,
                kind=kind,
                app_id=app_id or None,
                failures_only=failures_only,
                top=limit,
            )
        finally:
            session.close()
    show(rows, settings, f"{kind} sign ins", SIGN_IN_COLUMNS)


@logs.command("graph-activity")
@click.option("--workspace", default=None, help="Log Analytics workspace id.")
@click.option(
    "--app",
    "app_id",
    default="",
    help="Show only requests from this application id.",
)
@click.option("--hours", type=int, default=None, help="How far back to look.")
@click.option("--limit", type=int, default=None, help="Maximum rows to return.")
@click.pass_context
@handled
def logs_graph_activity(
    context: click.Context,
    workspace: str | None,
    app_id: str,
    hours: int | None,
    limit: int | None,
) -> None:
    """Read Microsoft Graph requests made against the tenant.

    This source exists only through Azure Monitor, and needs the
    MicrosoftGraphActivityLogs diagnostic category and a P1 or P2 licence.
    """
    settings = settings_of(context)
    config, client = logs_client(settings)
    rows = query_graph_activity(
        client,
        config,
        require_workspace(workspace),
        app_id=app_id,
        lookback_hours=hours,
        row_limit=limit,
    )
    show(rows, settings, "Microsoft Graph activity", GRAPH_ACTIVITY_COLUMNS)


@logs.command("kinds")
@click.pass_context
@handled
def logs_kinds(context: click.Context) -> None:
    """List the sign in kinds that can be read."""
    settings = settings_of(context)
    config: Config = settings["config"]
    rows = [
        {
            "kind": name,
            "diagnostic_category": entry.diagnostic_category,
            "graph_filter": entry.graph_filter,
        }
        for name, entry in sorted(config.tables.sign_in_kinds.items())
    ]
    columns = ("kind", "diagnostic_category", "graph_filter")
    show(rows, settings, "Sign in kinds", columns)


@cli.group()
def errors() -> None:
    """Explain authentication and authorisation error codes."""


@errors.command("explain")
@click.argument("code")
@click.pass_context
@handled
def errors_explain(context: click.Context, code: str) -> None:
    """Explain one error code, or a message carrying one.

    Needs no credentials, because the mapping is configuration.
    """
    settings = settings_of(context)
    config: Config = settings["config"]
    explanation = explain(code, config)
    show([explanation], settings, f"Error {explanation.code}", EXPLANATION_COLUMNS)
    if not explanation.known:
        raise SystemExit(EXIT_CHECKS_FAILED)


@errors.command("list")
@click.pass_context
@handled
def errors_list(context: click.Context) -> None:
    """List every error code entrascope can explain."""
    settings = settings_of(context)
    config: Config = settings["config"]
    rows = [explain(code, config) for code in known_codes(config)]
    show(rows, settings, "Known error codes", ("code", "meaning"))


@errors.command("search")
@click.argument("term")
@click.pass_context
@handled
def errors_search(context: click.Context, term: str) -> None:
    """Search the error codes by code fragment or by meaning."""
    settings = settings_of(context)
    config: Config = settings["config"]
    rows = list(search(term, config))
    show(rows, settings, f"Codes matching {term}", ("code", "meaning"))


@cli.group()
def serve() -> None:
    """Run entrascope as a Model Context Protocol server."""


@serve.command("stdio")
@click.pass_context
@handled
def serve_stdio(context: click.Context) -> None:
    """Serve the tools over stdio, for an assistant running on this machine.

    stdio has no OAuth, so credentials come from the environment or the
    credential file exactly as they do for every other command. Standard output
    carries the protocol, so logging goes to standard error as JSON lines.
    """
    from entrascope.mcp_stdio import build_server, run

    settings = settings_of(context)
    config: Config = settings["config"]
    run(build_server(config, settings.get("auth")))


@serve.command("http")
@click.option("--host", default=None, help="Address to bind inside the container.")
@click.option("--port", type=int, default=None, help="Port to listen on.")
@click.pass_context
@handled
def serve_http(context: click.Context, host: str | None, port: int | None) -> None:
    """Serve the tools over Streamable HTTP, as an OAuth 2.1 protected resource.

    Validates Entra issued bearer tokens. The audience must equal the
    application id URI, a token issued for anything else is refused, and the
    caller's token is never forwarded to Microsoft Graph.

    Terminate TLS at a reverse proxy and set the canonical URI, which appears
    in the protected resource metadata and which clients bind their tokens to.
    """
    from entrascope.mcp_http import run

    settings = settings_of(context)
    config: Config = settings["config"]
    if host or port:
        transport = config.server.transport.model_copy(
            update={
                key: value
                for key, value in (("host", host), ("port", port))
                if value is not None
            }
        )
        config = config.model_copy(
            update={"server": config.server.model_copy(update={"transport": transport})}
        )
    run(config)


def main() -> None:
    """Console script entry point."""
    cli(obj={})
