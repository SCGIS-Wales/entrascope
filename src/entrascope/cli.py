"""Command line surface.

The click group is the only public entry point. Every command delegates to a
free function in another module and renders through :mod:`entrascope.render`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from functools import wraps
from pathlib import Path
from typing import Any, cast

import click

from entrascope import __version__
from entrascope.config import Config, load_config
from entrascope.credentials import resolve_auth
from entrascope.discovery import (
    discover_applications,
    discover_service_principals,
    is_first_party,
)
from entrascope.doctor import run_checks
from entrascope.errors import explain, explain_api_error, known_codes, search
from entrascope.graph import graph_token_provider
from entrascope.http import Session, build_session
from entrascope.investigate import investigate as run_investigation
from entrascope.investigate import matches, matches_principal
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
    SEVERITY_ORDER,
    ApiCallError,
    AuthSource,
    ConfigError,
    CredentialError,
    Severity,
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
FINDING_COLUMNS = (
    "severity",
    "area",
    "subject",
    "occurrences",
    "detail",
    "remediation",
    "docs_url",
)

#: Where a log query is answered from.
ROUTES = ("graph", "monitor")

#: Short forms an engineer is likely to type. They resolve to the full name and
#: are deliberately absent from the help, so that one thing has one name there.
ALIASES = {"apps": "applications", "sps": "enterprise-apps"}


# framework contract: click resolves a command name through a Group method, so
# accepting an alias means overriding it. No logic beyond the lookup.
class AliasGroup(click.Group):
    """A command group that also answers to a short form of a command name."""

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        """Return the command, resolving a short form to its full name."""
        return super().get_command(ctx, ALIASES.get(cmd_name, cmd_name))

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        """Resolve a command, reporting the full name it resolved to."""
        _, command, remaining = super().resolve_command(ctx, args)
        return (command.name if command else None), command, remaining


#: One idea, described one way, wherever it appears.
APP_SELECTOR_HELP = (
    "Application id, object id, or part of a display name. Whichever of those "
    "the error message gave you."
)
ROUTE_HELP = (
    "Where to read from. The graph route uses the Microsoft Graph reporting "
    "API and works on any tenant. The monitor route uses a Log Analytics "
    "workspace and needs a diagnostic setting."
)
WORKSPACE_HELP = "Log Analytics workspace id. Required by the monitor route."
HOURS_HELP = "How far back to look, in hours."
LIMIT_HELP = "Greatest number of rows to return."
TYPE_HELP = (
    "Show only one application type, for example confidential-client, "
    "single-page-application, managed-identity or workload-identity-federation."
)
FIRST_PARTY_HELP = (
    "Include Microsoft first party enterprise applications. A tenant carries "
    "hundreds and they are Microsoft's to manage, so they are excluded by "
    "default."
)

ROOT_EPILOG = """
Terminology, used the same way throughout:


  application registration   what you register in Entra, the definition
  enterprise application     the service principal, the instance in a tenant
  delegated permission       acts as a signed in person, a scope claim
  application permission     acts as itself, a roles claim

Where to start:


  entrascope doctor                     can entrascope see what it needs
  entrascope investigate                what is wrong in this tenant
  entrascope investigate my-api         what is wrong with one application
  entrascope errors explain AADSTS50011 what does this code mean

Every command takes --output json or --output yaml, and --auth to choose an
identity. Run any command with --help for its own options.
"""

DISCOVER_EPILOG = """
Examples:


  entrascope discover applications --expiring
  entrascope discover applications --type single-page-application
  entrascope discover enterprise-apps --type managed-identity
  entrascope discover applications --app my-api --output json
"""

LOGS_EPILOG = """
Examples:


  entrascope logs audit --failures-only
  entrascope logs audit --app my-api
  entrascope logs signins --kind service-principal --failures-only
  entrascope logs signins --app 6fb17f1c-7c19-41a5-bd50-63a16bd7346b
  entrascope logs graph-activity --workspace <workspace-id>
  entrascope logs kinds

Entra directory operations do not appear in the Azure subscription activity
log. They are in the Entra audit logs, which logs audit reads.
"""

ERRORS_EPILOG = """
Examples:


  entrascope errors explain AADSTS7000215
  entrascope errors explain "AADSTS50011: The redirect URI does not match"
  entrascope errors search consent
  entrascope errors list

None of these need credentials, because the mapping is configuration.
"""

SERVE_EPILOG = """
Examples:


  entrascope serve stdio                      for an assistant on this machine
  entrascope serve http --port 8000           for a remote assistant, behind TLS
"""


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


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog=ROOT_EPILOG,
    no_args_is_help=True,
)
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

    entrascope reads. It never changes the directory, never grants consent and
    never rotates a credential. It tells you the command that would.

    Entra directory operations do not appear in the Azure subscription activity
    log. They are recorded in the Entra audit logs, which this tool reads
    through Microsoft Graph and through Azure Monitor.
    """
    context.ensure_object(dict)
    context.obj[SETTINGS] = build_settings(config_dir, auth, output, verbose)


@cli.command()
@click.argument("target", required=False, default="")
@click.option(
    "--severity",
    type=click.Choice(SEVERITY_ORDER),
    default=None,
    help="Show findings at this severity or worse. Errors describe something "
    "already broken, warnings something that will break, notes the context "
    "that explains a result.",
)
@click.option(
    "--kind",
    "kinds",
    multiple=True,
    help="Sign in kinds to read. Repeat the option. Every kind by default.",
)
@click.option("--limit", type=int, default=100, show_default=True)
@click.option(
    "--full",
    is_flag=True,
    help="Also show the applications, audit events and sign ins the findings "
    "were drawn from.",
)
@click.option("--include-first-party", is_flag=True, help=FIRST_PARTY_HELP)
@click.pass_context
@handled
def investigate(
    context: click.Context,
    target: str,
    severity: str | None,
    kinds: tuple[str, ...],
    limit: int,
    full: bool,
    include_first_party: bool,
) -> None:
    """Diagnose authentication and authorisation failures, ranked by severity.

    With no argument this sweeps the whole tenant, which is where to start when
    something is wrong but you do not know where. Give an application id, an
    object id or part of a display name to narrow it to one application.

    Findings combine expiring and expired credentials, failed directory
    operations, failed sign ins grouped by error code and explained, disabled
    enterprise applications, assignment requirements, insecure redirect URIs
    and applications with no owner.

        entrascope investigate                       everything, worst first
        entrascope investigate my-api --severity error   only what is broken
        entrascope investigate 6fb17f1c-7c19-41a5-bd50-63a16bd7346b
    """
    settings = settings_of(context)
    config, session, token = authenticated_session(settings)
    try:
        result = run_investigation(
            session,
            config,
            token,
            target=target,
            limit=limit,
            kinds=list(kinds) or None,
            minimum_severity=cast("Severity | None", severity),
            include_first_party=include_first_party,
        )
    finally:
        session.close()

    output: OutputFormat = settings.get("output", "table")
    if output != "table":
        emit(render([result], config, output))
        return

    for note in result.notes:
        emit_error(f"note: {note}")
    if not result.findings:
        emit(f"No findings for {result.target}.")
    else:
        emit(
            render(
                result.findings,
                config,
                output,
                title=f"Findings for {result.target}",
                columns=FINDING_COLUMNS,
            )
        )
    if full:
        show(result.applications, settings, "Applications", APPLICATION_COLUMNS)
        show(
            result.service_principals,
            settings,
            "Enterprise applications",
            SERVICE_PRINCIPAL_COLUMNS,
        )
        show(result.audit_events, settings, "Audit events", AUDIT_COLUMNS)
        show(result.sign_ins, settings, "Sign ins", SIGN_IN_COLUMNS)
    if result.errors():
        raise SystemExit(EXIT_CHECKS_FAILED)


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


@cli.group(cls=AliasGroup, epilog=DISCOVER_EPILOG, no_args_is_help=True)
def discover() -> None:
    """List application registrations and enterprise applications.

    An application registration is the definition you create in Entra. An
    enterprise application is the service principal, the instance of that
    definition inside a tenant. A failure can come from either, so both are
    listed separately.
    """


@discover.command("applications")
@click.option(
    "--filter",
    "filter_expression",
    default=None,
    help="OData filter passed to Microsoft Graph, for narrowing the query "
    "before it is sent.",
)
@click.option("--type", "application_type", default=None, help=TYPE_HELP)
@click.option("--app", "app_selector", default="", help=APP_SELECTOR_HELP)
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
    app_selector: str,
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
    if app_selector:
        rows = tuple(row for row in rows if matches(row, app_selector))
    if application_type:
        rows = tuple(row for row in rows if row.application_type == application_type)
    if expiring:
        rows = tuple(row for row in rows if row.expiring())
    show(rows, settings, "Application registrations", APPLICATION_COLUMNS)


@discover.command("enterprise-apps")
@click.option(
    "--filter",
    "filter_expression",
    default=None,
    help="OData filter passed to Microsoft Graph, for narrowing the query "
    "before it is sent.",
)
@click.option("--type", "application_type", default=None, help=TYPE_HELP)
@click.option("--app", "app_selector", default="", help=APP_SELECTOR_HELP)
@click.option(
    "--no-details",
    is_flag=True,
    help="Skip owners and role assignments, which need one call per application.",
)
@click.option("--include-first-party", is_flag=True, help=FIRST_PARTY_HELP)
@click.pass_context
@handled
def discover_service_principals_command(
    context: click.Context,
    filter_expression: str | None,
    application_type: str | None,
    app_selector: str,
    no_details: bool,
    include_first_party: bool,
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
    if not include_first_party:
        rows = tuple(row for row in rows if not is_first_party(row, config))
    if app_selector:
        rows = tuple(row for row in rows if matches_principal(row, app_selector))
    if application_type:
        rows = tuple(row for row in rows if row.application_type == application_type)
    show(rows, settings, "Enterprise applications", SERVICE_PRINCIPAL_COLUMNS)


@cli.group(epilog=LOGS_EPILOG, no_args_is_help=True)
def logs() -> None:
    """Read Entra and Azure Monitor logs.

    Entra directory operations do not appear in the Azure subscription activity
    log. They are in the Entra audit logs, which is what these commands read.
    """


@logs.command("audit")
@click.option(
    "--route",
    type=click.Choice(ROUTES),
    default="graph",
    show_default=True,
    help=ROUTE_HELP,
)
@click.option("--workspace", default=None, help=WORKSPACE_HELP)
@click.option("--hours", type=int, default=None, help=HOURS_HELP)
@click.option("--limit", type=int, default=None, help=LIMIT_HELP)
@click.option("--app", "app_selector", default="", help=APP_SELECTOR_HELP)
@click.option("--failures-only", is_flag=True, help="Show only operations that failed.")
@click.pass_context
@handled
def logs_audit(
    context: click.Context,
    route: str,
    workspace: str | None,
    hours: int | None,
    limit: int | None,
    app_selector: str,
    failures_only: bool,
) -> None:
    """Read directory changes to applications, the ApplicationManagement category."""
    settings = settings_of(context)
    if route == "monitor":
        config, client = logs_client(settings)
        rows = query_audit_monitor(
            client,
            config,
            require_workspace(workspace),
            target=app_selector,
            lookback_hours=hours,
            row_limit=limit,
        )
    else:
        config, session, _ = authenticated_session(settings)
        try:
            rows = query_audit_graph(session, config, top=limit)
        finally:
            session.close()
        if app_selector:
            rows = tuple(
                row for row in rows if app_selector.lower() in row.target.lower()
            )
    if failures_only:
        failures = set(settings["config"].fields.findings.audit_failure_results)
        rows = tuple(row for row in rows if row.result.lower() in failures)
    show(rows, settings, "Application management audit events", AUDIT_COLUMNS)


@logs.command("signins")
@click.option("--kind", default="interactive", help="Which sign in kind to read.")
@click.option(
    "--route",
    type=click.Choice(ROUTES),
    default="graph",
    show_default=True,
    help=ROUTE_HELP,
)
@click.option("--workspace", default=None, help=WORKSPACE_HELP)
@click.option("--app", "app_id", default="", help=APP_SELECTOR_HELP)
@click.option("--failures-only", is_flag=True, help="Show only sign ins that failed.")
@click.option("--hours", type=int, default=None, help=HOURS_HELP)
@click.option("--limit", type=int, default=None, help=LIMIT_HELP)
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
@click.option("--app", "app_id", default="", help=APP_SELECTOR_HELP)
@click.option("--hours", type=int, default=None, help=HOURS_HELP)
@click.option("--limit", type=int, default=None, help=LIMIT_HELP)
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


@cli.group(epilog=ERRORS_EPILOG, no_args_is_help=True)
def errors() -> None:
    """Explain authentication and authorisation error codes."""


@errors.command("explain", no_args_is_help=True)
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


@errors.command("search", no_args_is_help=True)
@click.argument("term")
@click.pass_context
@handled
def errors_search(context: click.Context, term: str) -> None:
    """Search the error codes by code fragment or by meaning."""
    settings = settings_of(context)
    config: Config = settings["config"]
    rows = list(search(term, config))
    show(rows, settings, f"Codes matching {term}", ("code", "meaning"))


@cli.group(epilog=SERVE_EPILOG, no_args_is_help=True)
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
