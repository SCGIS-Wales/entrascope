"""Command line surface.

The click group is the only public entry point. Every command delegates to a
free function in another module and renders through :mod:`entrascope.render`.
"""

from __future__ import annotations

import os
import sys
from collections.abc import (
    Callable,
    Iterator,
    Mapping,
    MutableMapping,
    Sequence,
)
from contextlib import contextmanager
from functools import wraps
from importlib import import_module
from importlib.util import find_spec
from pathlib import Path
from typing import Any, NoReturn, cast

import click

from entrascope import __version__
from entrascope.capabilities import (
    grant_command,
    permissions_by_name,
    permissions_named_in,
)
from entrascope.config import (
    Config,
    candidate_directories,
    downloads_dir,
    effective,
    load_config,
    packaged_config_dir,
    read_text_file,
    repository_config_dir,
    user_config_dir,
)
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
from entrascope.identity import graph_session_for
from entrascope.identity import whoami as run_whoami
from entrascope.inspect import Catalogue, read_catalogue, search_gallery
from entrascope.inspect import inspect as run_inspect
from entrascope.investigate import investigate as run_investigation
from entrascope.investigate import matches, matches_principal
from entrascope.logger import (
    bind_context,
    configure_logging,
    get_logger,
    new_correlation_id,
)
from entrascope.logs import (
    looks_like_identifier,
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
    AuthContext,
    AuthSource,
    ConfigError,
    CredentialError,
    EntrascopeError,
    Investigation,
    Severity,
)
from entrascope.monitor import build_logs_client
from entrascope.picker import Choice, available, choose
from entrascope.redaction import redact_with_config
from entrascope.render import (
    EXIT_API,
    EXIT_CHECKS_FAILED,
    EXIT_CONFIG,
    EXIT_CREDENTIALS,
    EXIT_INTERRUPTED,
    OUTPUT_FORMATS,
    OutputFormat,
    count_summary,
    emit,
    emit_error,
    exit_code_for_checks,
    portal_link,
    render,
    render_record,
    show_checks,
    show_yaml,
    to_payload,
    working,
    yaml_text,
)
from entrascope.render import show as show_rows
from entrascope.stream import follow as follow_tenant
from entrascope.stream import rows_from
from entrascope.upgrade import (
    describe_installation,
    latest_release,
    newer_release,
    run_upgrade,
    tail,
    upgrade_notice,
)

log = get_logger(__name__)

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


def with_timezone(config: Config, zone: str) -> Config:
    """Return configuration that shows timestamps in one zone."""
    display = config.fields.display
    timestamp = display.timestamp.model_copy(update={"zone": zone})
    return config.model_copy(
        update={
            "fields": config.fields.model_copy(
                update={"display": display.model_copy(update={"timestamp": timestamp})}
            )
        }
    )


def announce_new_version(config: Config, output: str) -> None:
    """Say once, quietly, that a newer version exists.

    Never for machine readable output, never without a terminal, never more
    than once a day, and never loudly enough to be mistaken for the answer.
    """
    try:
        if output in ("json", "yaml", "plain") or not sys.stderr.isatty():
            return
        release = newer_release(config)
        if release is not None:
            emit_error(upgrade_notice(release))
    except Exception:
        # Belt as well as braces. The check has its own boundary, and this one
        # is here so that no future change to it can stop a command running.
        log.debug("the version notice was skipped", exc_info=True)


def build_settings(
    config_dir: Path | None,
    auth: str | None,
    output: str,
    verbose: bool,
    timezone: str | None = None,
    credential_file: str | None = None,
) -> dict[str, Any]:
    """Load configuration and prepare the shared settings for every command."""
    config = load_config(config_dir)
    if timezone:
        config = with_timezone(config, timezone)
    configure_logging(config, surface="cli", level=log_level(output, verbose))
    new_correlation_id()
    if auth:
        bind_context(auth_source=auth)
    announce_new_version(config, output)
    return {
        "config": config,
        "auth": auth,
        "output": output,
        "credential_file": credential_file,
    }


def settings_of(context: click.Context) -> dict[str, Any]:
    """Return the shared settings from the click context.

    The settings are placed on the root context by the group callback, so a
    subcommand and the error handler both find them by walking up. The dict
    itself is returned rather than a copy, because a command records what it
    authenticated as and the error handler reads it back.
    """
    current: click.Context | None = context
    while current is not None:
        values = current.obj or {}
        result = values.get(SETTINGS) if isinstance(values, dict) else None
        if isinstance(result, dict):
            return result
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
#: What a table shows. Fewer columns, because a terminal that has to elide
#: every one of them shows nothing at all. The identifiers and the rest of the
#: record are in --output plain, json and yaml.
AUDIT_TABLE_COLUMNS = ("timestamp", "activity", "result", "initiated_by", "target")
#: Added to the table when something failed, because the reason is the point.
AUDIT_FAILURE_COLUMNS = (
    "timestamp",
    "activity",
    "result",
    "reason",
    "initiated_by",
    "target",
)
AUDIT_COLUMNS = (*AUDIT_TABLE_COLUMNS, "target_type", "target_id")
APPLICATION_TABLE_COLUMNS = (
    "display_name",
    "application_type",
    "audience_label",
    "credentials",
)
SERVICE_PRINCIPAL_TABLE_COLUMNS = (
    "display_name",
    "application_type",
    "account_enabled",
    "app_role_assignment_required",
)
SIGN_IN_TABLE_COLUMNS = (
    "timestamp",
    "identity",
    "app_display_name",
    "error_code",
    "failure_reason",
)
# A count of one, repeated down a column, tells nobody anything: where a
# finding groups several events the detail says how many, in words. What was
# missing was which application, exactly, and when.
FINDING_TABLE_COLUMNS = ("severity", "area", "subject", "identifier", "when", "detail")
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
#: The table columns, and then what a table has no room for.
FINDING_COLUMNS = (*FINDING_TABLE_COLUMNS, "remediation", "docs_url")

#: Where a log query is answered from.
ROUTES = ("graph", "monitor")

#: The category name that means every category rather than one. It is a key in
#: config/tables.yaml like any other; named here only so the heading can say
#: "every category" rather than repeat the word.
EVERY_CATEGORY = "all"

#: Short forms an engineer is likely to type. They resolve to the full name and
#: are deliberately absent from the help, so that one thing has one name there.
ALIASES = {"apps": "applications", "sps": "enterprise-apps"}

#: Commands that have been folded into another one. Listing applications and
#: reading one of them were two commands asking the same question at two
#: depths, so discover is now inspect. The old name still works, because
#: breaking somebody's script to tidy up a command list is not a fair trade.
RENAMED = {"discover": "inspect"}


def global_options() -> list[click.Parameter]:
    """Return the options that may be given before or after a subcommand.

    Nobody should have to remember which side of the subcommand an option goes
    on. These are declared on the group and on every command, and a value given
    later wins.
    """
    return [
        click.Option(
            ["--auth"],
            type=click.Choice(AUTH_SOURCE_ORDER),
            default=None,
            help=AUTH_HELP,
        ),
        click.Option(
            ["--output"],
            type=click.Choice(OUTPUT_FORMATS),
            default=None,
            help=OUTPUT_HELP,
        ),
        click.Option(["--verbose"], is_flag=True, default=None, help=VERBOSE_HELP),
        click.Option(
            ["--timezone"],
            type=click.Choice(TIMEZONES),
            default=None,
            help=TIMEZONE_HELP,
        ),
    ]


# framework contract: click decides which options a command accepts through a
# Command subclass, so accepting the global ones after a subcommand means
# overriding it. The merging itself is a free function.
class GlobalOptionCommand(click.Command):
    """A command that also accepts the options declared on the root group."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.params.extend(global_options())

    def invoke(self, ctx: click.Context) -> Any:
        """Apply any global option given after the subcommand, then run."""
        apply_overrides(ctx, pop_global_options(ctx))
        return super().invoke(ctx)


#: The options accepted on either side of a subcommand, named once so that the
#: declaration and the two places that consume them cannot drift apart.
GLOBAL_OPTION_NAMES = ("auth", "output", "verbose", "timezone")


def pop_global_options(context: click.Context) -> dict[str, Any]:
    """Take the global options off a command's parameters and return them.

    They are declared on the group and on every command, so the same value
    arrives twice and only the one given later should win. Taking them off here
    leaves each command's own signature untouched.
    """
    return {
        name: context.params.pop(name)
        for name in GLOBAL_OPTION_NAMES
        if name in context.params
    }


def apply_overrides(context: click.Context, overrides: Mapping[str, Any]) -> None:
    """Merge options given after a subcommand into the shared settings."""
    settings = settings_of(context)
    if not settings:
        return
    changed = {name: value for name, value in overrides.items() if value}
    if not changed:
        return
    settings.update(
        {key: value for key, value in changed.items() if key in ("auth", "output")}
    )
    if changed.get("timezone"):
        settings["config"] = with_timezone(settings["config"], str(changed["timezone"]))
    root = context.find_root()
    root.obj[SETTINGS] = settings
    configure_logging(
        settings["config"],
        surface="cli",
        level=log_level(settings.get("output", "table"), bool(changed.get("verbose"))),
    )
    if changed.get("auth"):
        bind_context(auth_source=str(changed["auth"]))


def nested_paths(group: click.Group, name: str) -> list[str]:
    """Return the full path of every command with one name, at any depth.

    Somebody who types the name of a subcommand at the top level has the right
    idea and the wrong path. Telling them the path is more use than telling
    them the command does not exist.
    """
    found: list[str] = []
    for group_name, command in sorted(group.commands.items()):
        if not isinstance(command, click.Group):
            continue
        for child in sorted(command.commands):
            resolved = ALIASES.get(name, name)
            if child in (name, resolved):
                found.append(f"{group_name} {child}")
    return found


def help_for(root: click.Group, ctx: click.Context, path: str) -> str:
    """Return the help of a command named by its path below the root."""
    group_name, command_name = path.split(" ", 1)
    group = root.get_command(ctx, group_name)
    if not isinstance(group, click.Group):
        return ""
    command = group.get_command(ctx, command_name)
    if command is None:
        return ""
    # No parent context, because the usage line already carries the full path
    # and click would otherwise prefix the programme name a second time.
    child = click.Context(command, info_name=f"entrascope {path}")
    return command.get_help(child)


# framework contract: click decides what a group does with no subcommand
# through a Group method, so offering a choice means overriding it. The
# choosing itself is entrascope.picker.
class GuidedGroup(click.Group):
    """A group that offers its commands rather than only listing them.

    Printing the help and returning to the shell tells somebody what exists and
    then makes them type it again. With a terminal to draw on, the commands are
    offered instead, and the one chosen is run. Without one, in a pipe or a
    script, the help is printed exactly as before.
    """

    command_class = GlobalOptionCommand

    def invoke(self, ctx: click.Context) -> Any:
        """Run the subcommand, or offer the choice when there is none."""
        result = super().invoke(ctx)
        if ctx.invoked_subcommand is not None:
            return result
        emit(ctx.get_help())
        return offer_commands(self, ctx)


#: The key the chooser returns for the way out of a menu. It is not a command
#: name, and no command can be called this.
LEAVE = "\x00leave"


def offer_commands(group: click.Group, ctx: click.Context) -> Any:
    """Offer a group's commands, run what is chosen, and offer them again.

    A tool somebody is exploring should not put them back at the shell every
    time they finish reading something. The menu returns after each command,
    and the way out is offered rather than guessed at. Escape does the same,
    so a group reached from the main menu comes back to it.

    A command that needs an argument asks for it, rather than being run and
    then complaining that it is missing. A command that fails says so and the
    menu returns, because losing a session over a typo is miserable.
    """
    if not available():
        return None
    try:
        return run_menu(group, ctx)
    except KeyboardInterrupt:
        # A menu is drawn outside any command, so the interrupt handling every
        # command has does not cover it. Without this, control C at a menu
        # gives click's own "Aborted!" and exit code 1, where everywhere else
        # in the tool it says "Interrupted." and exits 130, which is what a
        # shell expects from an interrupted process.
        leave_now()


def run_menu(group: click.Group, ctx: click.Context) -> Any:
    """Draw the menu, run what is chosen, and draw it again."""
    root = ctx.find_root().command is group
    lines = [
        Choice(key=name, label=f"{name:<18} {summary(command)}")
        for name, command in sorted(group.commands.items())
        if not command.hidden
    ]
    lines.append(
        Choice(
            key=LEAVE,
            label=f"{'leave':<18} " + ("close entrascope" if root else "go back"),
            tone="quiet",
        )
    )
    title = "entrascope" if root else f"entrascope {group.name}"
    result: Any = None
    while True:
        emit("")
        picked = choose(lines, title=title, **palette(settings_of(ctx).get("config")))
        if picked is None or picked == LEAVE:
            return result
        command = group.get_command(ctx, picked)
        if command is None:
            return result
        result = attempt(command, picked, ctx)
        # The menu is drawn over whatever is on the screen, so redrawing it the
        # moment a command finishes wipes what the command just said. Waiting
        # for a keystroke is what makes the output readable, and it is also
        # where somebody scrolls back through it.
        click.pause("Press any key to go back to the menu ")


def attempt(command: click.Command, name: str, ctx: click.Context) -> Any:
    """Run a command from a menu, reporting a failure rather than leaving.

    Everything the tool raises deliberately is worth reading and then carrying
    on from. A failure to authenticate or a mistyped identifier should not end
    a session that took a moment to start.
    """
    try:
        return run_command(command, name, ctx)
    except (EntrascopeError, click.ClickException) as error:
        emit_error(str(error))
    except click.Abort:
        emit_error("Cancelled.")
    except SystemExit as ending:
        # A command reports a bad result by exiting with a code. From a menu
        # that would end the session over a finding, which is not what an exit
        # code is for, so the code is noted and the menu returns.
        if ending.code not in (0, None):
            emit_error(f"That command finished with exit code {ending.code}.")
    return None


def palette(config: Config | None) -> dict[str, Any]:
    """Return the chooser's colours as keyword arguments for the chooser.

    Colour is configuration, so a site that reads a light terminal or a
    colourblind engineer can change it without a code change.
    """
    if config is None:
        return {}
    chooser = config.fields.display.chooser
    return {
        "scheme": {
            "background": chooser.background,
            "foreground": chooser.foreground,
            "highlight": chooser.highlight,
            "heading": chooser.heading,
            "hint": chooser.hint,
        },
        "tones": dict(chooser.tones),
    }


def summary(command: click.Command) -> str:
    """Return the first line of a command's help."""
    return (command.get_short_help_str(80) or "").strip()


def run_command(command: click.Command, name: str, ctx: click.Context) -> Any:
    """Run one command, asking for any argument it cannot do without."""
    answers: list[str] = []
    for parameter in command.params:
        if isinstance(parameter, click.Argument) and parameter.required:
            label = (parameter.name or "value").replace("_", " ")
            # Answering nothing goes back. A prompt with no way out but the
            # interrupt key is a trap, and the menu is one keystroke away.
            answer = click.prompt(
                f"{label.capitalize()} (blank to go back)",
                default="",
                show_default=False,
                type=str,
            ).strip()
            if not answer:
                return None
            answers.append(answer)
    # Everything typed at a prompt is a value, never an option. Without the
    # separator, an error message that happens to begin with a dash, or the
    # word --help, would be parsed rather than answered.
    arguments = ["--", *answers] if answers else []
    with command.make_context(name, arguments, parent=ctx) as inner:
        return command.invoke(inner)


# framework contract: click reports an unknown command through a Group method,
# so improving that message means overriding it. The search is a free function.
class RootGroup(GuidedGroup):
    """The top level group, which knows where its subcommands live."""

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        """Return the command, answering to a name it used to be called."""
        return super().get_command(ctx, RENAMED.get(cmd_name, cmd_name))

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        """Resolve a command, pointing at the right path when there is one."""
        name = args[0] if args else ""
        if name and self.get_command(ctx, name) is None:
            paths = nested_paths(self, name)
            if paths:
                # Show the help for what they meant, not only where it lives.
                # Somebody who has just been corrected wants the options, and
                # asking them to type a second command to get them is rude.
                for path in paths:
                    emit(help_for(self, ctx, path))
                suggestion = " or ".join(f"entrascope {path}" for path in paths)
                ctx.fail(
                    f"No such command {name!r} at the top level. "
                    f"It is a subcommand: try {suggestion}."
                )
        return super().resolve_command(ctx, args)


# framework contract: click resolves a command name through a Group method, so
# accepting an alias means overriding it. No logic beyond the lookup.
class AliasGroup(GuidedGroup):
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


#: The global options, described once and accepted on either side of a
#: subcommand.
AUTH_HELP = (
    "Authentication source to use. Naming one selects it whether or not it is "
    "enabled for automatic resolution. Without this, the credential file is "
    "tried and then the Azure CLI session."
)
OUTPUT_HELP = "Output format."
VERBOSE_HELP = "Log at debug level, including what the libraries report."
TIMEZONE_HELP = (
    "Zone to show timestamps in. Microsoft Graph records in UTC. Either way "
    "the zone is named on every timestamp."
)
TIMEZONES = ("utc", "local")
PICK_HELP = (
    "Number the lines and ask which one to open, then show that record whole "
    "with its explanation and a link into the portal."
)

#: One idea, described one way, wherever it appears.
CREDENTIALS_HELP = (
    "Credential file to use. A bare name is taken as a file inside ~/.entra, "
    "so --credentials provisioner-credentials-stage.json picks the one next to "
    "the default. A path is used as given. Naming one means the file source."
)
APP_SELECTOR_HELP = (
    "Application id, object id, or part of a display name. Whichever of those "
    "the error message gave you."
)
FILTER_HELP = (
    "OData filter passed to Microsoft Graph, for narrowing the query before it is sent."
)
ROUTE_HELP = (
    "Where to read from. The graph route uses the Microsoft Graph reporting "
    "API and works on any tenant. The monitor route uses a Log Analytics "
    "workspace and needs a diagnostic setting."
)
WORKSPACE_HELP = "Log Analytics workspace id. Required by the monitor route."
GRAPH_ACTIVITY_WORKSPACE_HELP = (
    "Log Analytics workspace id. Always required here, because this source "
    "exists only through Azure Monitor. Set workspace_id in config/tables.yaml "
    "to stop being asked."
)
HOURS_HELP = (
    "How far back to look, in hours. Applied by the service on both routes, so "
    "the rows returned are the newest inside the period rather than the newest "
    "of all."
)
LIMIT_HELP = "Greatest number of rows to return."
CATEGORY_HELP = (
    "Audit category to read. Application management by default, which is where "
    "changes to applications are recorded. Pass all for every category, and "
    "run entrascope logs categories for the list."
)
TYPE_HELP = (
    "Show only one application type, for example confidential-client, "
    "single-page-application, managed-identity or workload-identity-federation."
)
EVERYTHING_HELP = (
    "Offer everything, including Microsoft first party applications and the "
    "managed identities Azure creates for its own resources. A tenant holds "
    "hundreds of both and they are almost never what somebody is looking for."
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

INSPECT_EPILOG = """
Examples:


  entrascope inspect                          choose from the list
  entrascope inspect saml2                    one application, by name
  entrascope inspect applications --expiring
  entrascope inspect applications --type single-page-application
  entrascope inspect enterprise-apps --type managed-identity
  entrascope inspect applications --app my-api --output json
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
    settings: MutableMapping[str, Any],
) -> tuple[Config, Session, Callable[[], str]]:
    """Resolve an identity, build a session, and return the token provider too.

    The provider is returned rather than taken back off the session, because
    the session holds a requests auth callable and not a token provider, and
    the two have different signatures.
    """
    config: Config = settings["config"]
    context, credential = resolve_auth(
        config, settings.get("auth"), named=settings.get("credential_file")
    )
    bind_context(auth_source=context.source, tenant_id=context.tenant_id or "")
    # Remembered so that a failure later can say which identity was used and
    # what was passed over to reach it. Both are the first questions asked.
    settings["identity"] = context
    token = graph_token_provider(config, credential)
    return config, build_session(config, token), token


@contextmanager
def graph_session(
    settings: MutableMapping[str, Any],
) -> Iterator[tuple[Config, Session, Callable[[], str]]]:
    """Yield an authenticated Graph session and close it afterwards.

    Every command that reads from Graph opens one and has to remember to close
    it. Eight repetitions of the same try and finally is eight chances to
    forget, and a session left open holds a connection pool until the process
    ends.
    """
    config, session, token = authenticated_session(settings)
    try:
        yield config, session, token
    finally:
        session.close()


def logs_client(settings: Mapping[str, Any]) -> tuple[Config, Any]:
    """Resolve an identity and build the Log Analytics client."""
    config: Config = settings["config"]
    _, credential = resolve_auth(
        config, settings.get("auth"), named=settings.get("credential_file")
    )
    return config, build_logs_client(credential, config)


def require_workspace(workspace: str | None, config: Config, source: str = "") -> str:
    """Return the workspace identifier, or explain what to do without one."""
    resolved = workspace or config.tables.workspace_id
    if resolved:
        return resolved
    alternative = (
        "This source exists only through Azure Monitor, so without a workspace "
        "there is nothing to read. Use entrascope logs audit, which reads "
        "through Microsoft Graph and needs no workspace, or entrascope "
        "investigate, which uses whatever is available."
        if source == "graph-activity"
        else "Or use --route graph, which reads the same events through "
        "Microsoft Graph and needs no workspace."
    )
    raise ConfigError(
        "The Azure Monitor route needs a Log Analytics workspace, and none is "
        "configured.\n"
        "  Pass --workspace with the workspace id, or set workspace_id in "
        "config/tables.yaml to stop being asked.\n"
        "  Exporting logs to a workspace also needs a diagnostic setting, the "
        "Security Administrator role, and Entra ID P1 or P2 for the sign in "
        "categories. Run entrascope doctor to see which are in place.\n"
        f"  {alternative}"
    )


def narrowed[Row](
    rows: Sequence[Row],
    app_selector: str,
    application_type: str | None,
    matcher: Callable[[Row, str], bool],
) -> tuple[Row, ...]:
    """Narrow a listing by the selector and the type, the way every listing does.

    Both listings take the same two options and mean the same thing by them.
    The only difference is how an application is matched, because a
    registration and an enterprise application are matched on different fields.
    """
    found = tuple(rows)
    if app_selector:
        found = tuple(row for row in found if matcher(row, app_selector))
    if application_type:
        found = tuple(
            row
            for row in found
            if getattr(row, "application_type", None) == application_type
        )
    return found


def route_options[Function: Callable[..., Any]](command: Function) -> Function:
    """Add the two options that decide where a log query is answered from.

    They belong together: naming the monitor route without a workspace cannot
    work, and a workspace means nothing on the graph route. Declaring them once
    keeps the two log commands describing them the same way.
    """
    for option in (
        click.option("--workspace", default=None, help=WORKSPACE_HELP),
        click.option(
            "--route",
            type=click.Choice(ROUTES),
            default="graph",
            show_default=True,
            help=ROUTE_HELP,
        ),
    ):
        command = option(command)
    return command


def audit_title(config: Config, category: str | None) -> str:
    """Return the heading for a listing of audit events.

    Naming the category is the difference between a reader knowing they are
    looking at part of the audit log and assuming they are looking at all of it.
    """
    name = category or config.tables.default_audit_category
    if name == EVERY_CATEGORY:
        return "Audit events, every category"
    return f"Audit events, {name.replace('-', ' ')}"


def show(
    rows: Sequence[Any],
    settings: Mapping[str, Any],
    title: str,
    columns: Sequence[str],
    noun: str = "rows",
    table_columns: Sequence[str] | None = None,
) -> None:
    """Render rows in the requested format and write them out.

    A table shows the columns worth reading on a terminal. Every other format
    carries the whole record, so nothing is lost, it is just not in the way.
    """
    config: Config = settings["config"]
    output: OutputFormat = settings.get("output", "table")
    narrow = output == "table" and table_columns is not None
    summary = count_summary(rows, noun)
    if narrow and rows:
        summary = f"{summary}. Use --output plain for every field."
    show_rows(
        rows,
        config,
        output,
        title=title,
        columns=table_columns if narrow else columns,
        summary=summary,
    )


#: How to get the server dependencies, and how to repair them.
MCP_MISSING = (
    "fastmcp is not installed. It is a dependency of entrascope, so this "
    "install is incomplete.\n"
    "  pip install --force-reinstall --no-cache-dir entrascope"
)
MCP_BROKEN = (
    "fastmcp is installed but cannot be imported. This is usually fastmcp and "
    "fastmcp-slim having overlaid the same directory, which leaves it without "
    "its __init__ file.\n"
    "  pip install --force-reinstall --no-cache-dir entrascope\n"
    "The underlying error was: {error}"
)


def import_server(module: str) -> Any:
    """Import one of the server modules, explaining a failure in a sentence.

    A missing or half installed dependency is a common way to meet this tool,
    and a stack trace out of an import tells the reader nothing they can act
    on.
    """
    try:
        return import_module(f"entrascope.{module}")
    except ImportError as error:
        if find_spec("fastmcp") is None:
            raise ConfigError(MCP_MISSING) from error
        raise ConfigError(MCP_BROKEN.format(error=error)) from error


def leave_now() -> NoReturn:
    """Report an interrupt and exit at once.

    Raising SystemExit here would run the interpreter's shutdown, which joins
    every worker thread and prints a second traceback over the top of the
    first. An engineer who pressed control C wants the process gone. Output is
    flushed first, so nothing already produced is lost.
    """
    emit_error("Interrupted.")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(EXIT_INTERRUPTED)


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
    identity = settings.get("identity")
    context_lines: list[str] = []
    if isinstance(identity, AuthContext):
        context_lines.append(f"\nAuthenticated as: {identity.description}.")
        if identity.skipped:
            context_lines.append(
                "Passed over on the way: " + "; ".join(identity.skipped) + "."
            )
    explanation = explain_api_error(error.error, config)
    if not explanation.known:
        return "\n".join(context_lines)
    lines = [*context_lines, f"\n{explanation.code}: {explanation.meaning}"]
    if explanation.likely_cause:
        lines.append(f"Likely cause: {explanation.likely_cause}")
    lines.append(f"Remediation: {explanation.remediation}")
    lines.append(f"See: {explanation.docs_url}")
    exact = exact_grant(error, identity, config)
    if exact:
        lines.append(exact)
    return "\n".join(line.strip() for line in lines)


def exact_grant(error: ApiCallError, identity: object, config: Config) -> str:
    """Return the command that grants what a refusal named, if it named one.

    Microsoft says which permission it wanted, and entrascope knows the
    identifier for it and the application it authenticated as. Printing the
    exact command beats telling somebody to look one up.
    """
    named = permissions_named_in(error.error.message, config)
    if not named:
        return ""
    client_id = (
        identity.client_id
        if isinstance(identity, AuthContext) and identity.client_id
        else "<client-id>"
    )
    command = grant_command(permissions_by_name(named, config), config, client_id)
    if not command:
        return ""
    return (
        f"\nGrant it with:\n{command}\n"
        "Adding a permission records a requirement. The consent is what grants "
        "it, and both lines are needed."
    )


def pick_one(
    rows: Sequence[Any], settings: Mapping[str, Any], columns: Sequence[str]
) -> None:
    """Number the rows, ask for one, and show it whole.

    A listing answers what happened. Picking a line answers what happened to
    that one thing, which is the next question every time.
    """
    config: Config = settings["config"]
    if not rows:
        return
    numbered = [
        {"#": str(index + 1), **to_payload(row)} for index, row in enumerate(rows)
    ]
    show_rows(
        numbered,
        config,
        "table",
        title="Pick a line",
        columns=("#", *columns),
        summary="",
    )
    choice = click.prompt(
        "Line to open, or nothing to stop",
        default="",
        show_default=False,
        type=str,
    ).strip()
    if not choice:
        return
    if not choice.isdigit() or not 1 <= int(choice) <= len(rows):
        emit_error(f"There is no line {choice}.")
        raise SystemExit(EXIT_CONFIG)
    chosen = rows[int(choice) - 1]
    emit("")
    emit(render_record(chosen, config, title="The whole record"))
    emit(explain_record(chosen, config))


def explain_record(row: Any, config: Config) -> str:
    """Explain whatever a record says went wrong, and where to look next."""
    payload = to_payload(row)
    if not isinstance(payload, Mapping):
        return ""
    code = str(payload.get("reason") or payload.get("failure_reason") or "")
    error_code = payload.get("error_code")
    if isinstance(error_code, int) and error_code:
        code = f"AADSTS{error_code}"
    lines: list[str] = []
    if code:
        explanation = explain(code, config)
        if explanation.known:
            lines.extend(
                [
                    "",
                    f"{explanation.code}: {explanation.meaning}",
                    f"Remediation: {explanation.remediation}",
                    f"See: {explanation.docs_url}",
                ]
            )
    link = portal_link(payload, "target", config) or portal_link(
        payload, "display_name", config
    )
    if link:
        lines.extend(["", f"In the portal: {link}"])
    return "\n".join(lines)


def handled[Returns](function: Callable[..., Returns]) -> Callable[..., Returns]:
    """Turn the deliberate errors into a message and an exit code.

    A stack trace helps nobody diagnose a tenant. Every error entrascope raises
    on purpose already carries its own remediation, so it is printed as it is.
    """

    @wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Returns:
        try:
            return function(*args, **kwargs)
        except KeyboardInterrupt:
            leave_now()
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
        # Last, because the three above are all kinds of this one. Anything
        # entrascope raises on purpose carries its own remediation, and a
        # refusal printed as a stack trace reads as a crash rather than as the
        # considered answer it is.
        except EntrascopeError as error:
            emit_error(str(error))
            raise SystemExit(EXIT_CHECKS_FAILED) from error

    return wrapper


@click.group(
    cls=RootGroup,
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog=ROOT_EPILOG,
    invoke_without_command=True,
)
@click.version_option(__version__, prog_name="entrascope")
@click.option(
    "--auth", type=click.Choice(AUTH_SOURCE_ORDER), default=None, help=AUTH_HELP
)
@click.option(
    "--output",
    type=click.Choice(OUTPUT_FORMATS),
    default="table",
    show_default=True,
    help=OUTPUT_HELP,
)
@click.option(
    "--config-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Directory holding the configuration files.",
)
@click.option("--credentials", "credential_file", default=None, help=CREDENTIALS_HELP)
@click.option("--verbose", is_flag=True, help=VERBOSE_HELP)
@click.pass_context
@handled
def cli(
    context: click.Context,
    auth: str | None,
    output: str,
    config_dir: Path | None,
    credential_file: str | None,
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
    context.obj[SETTINGS] = build_settings(
        config_dir, auth, output, verbose, None, credential_file
    )


@cli.command(cls=GlobalOptionCommand)
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
@click.option(
    "--follow",
    "-f",
    is_flag=True,
    help="Watch the tenant rather than report on it once. The audit log and "
    "the sign in logs stream newest first, coloured by severity, and typing "
    "narrows them by keyword.",
)
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
    follow: bool,
) -> None:
    """Diagnose authentication and authorisation failures, ranked by severity.

    With no argument this sweeps the whole tenant, which is where to start when
    something is wrong but you do not know where. Give an application id, an
    object id or part of a display name to narrow it to one application.

    Findings combine expiring and expired credentials, failed directory
    operations, failed sign ins grouped by error code and explained, disabled
    enterprise applications, assignment requirements, insecure redirect URIs
    and applications with no owner.

    \b
        entrascope investigate                       everything, worst first
        entrascope investigate my-api --severity error   only what is broken
        entrascope investigate --follow                  watch it live
        entrascope investigate 6fb17f1c-7c19-41a5-bd50-63a16bd7346b
    """
    settings = settings_of(context)
    with (
        graph_session(settings) as (config, session, token),
        working(f"Investigating {target}" if target else "Investigating the tenant"),
    ):
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

    output: OutputFormat = settings.get("output", "table")
    if output != "table":
        if follow:
            emit_error(
                "The live view draws a screen, so it cannot be combined with "
                f"--output {output}. Reporting once instead."
            )
        emit(render([result], config, output))
        return

    for note in result.notes:
        emit_error(f"note: {note}")
    if not result.findings:
        emit(f"No findings for {result.target}.")
    else:
        errors = len(result.errors())
        show_rows(
            result.findings,
            config,
            output,
            title=f"Findings for {result.target}",
            columns=(FINDING_TABLE_COLUMNS if output == "table" else FINDING_COLUMNS),
            summary=(
                f"{len(result.findings)} findings, {errors} of them errors. "
                "Use --output plain for the remediation and the documentation."
            ),
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

    if follow or (available() and after_findings(result, config) == "watch"):
        watch(result, config, token, kinds=list(kinds))
        return
    if result.errors():
        raise SystemExit(EXIT_CHECKS_FAILED)


#: What somebody might want once an investigation has reported.
AFTER_FINDINGS: tuple[tuple[str, str], ...] = (
    ("watch", "watch the tenant live, newest first"),
    ("save", "save these findings to a YAML file"),
    ("back", "back to the menu"),
)


def after_findings(result: Investigation, config: Config) -> str:
    """Offer what to do next, rather than returning to the shell."""
    emit("")
    chosen = choose(
        [Choice(key=key, label=label) for key, label in AFTER_FINDINGS],
        title="Next",
        **palette(config),
    )
    if chosen == "save":
        save_findings(result, config)
    return chosen or "back"


def save_findings(result: Investigation, config: Config) -> None:
    """Write one investigation to a YAML file named after what it looked at."""
    path = free_name(safe_name(f"investigation-{result.target}", "investigation"))
    path.write_text(yaml_text(to_payload(result), config), encoding="utf-8")
    emit(f"Saved to {path}")


def watch(
    result: Investigation,
    config: Config,
    token: Callable[[], str],
    *,
    kinds: Sequence[str],
) -> None:
    """Open the live view on what the investigation already read.

    The token source outlives the session it was used with, so the view takes
    the one the investigation authenticated with rather than authenticating a
    second time. An empty screen and a wait of one polling interval is a poor
    way to start, so what has been read already is what it opens on.
    """
    follow_tenant(
        config,
        token,
        kinds=kinds or None,
        app_id=identifier_of(result),
        initial=rows_from(result, config),
    )


def identifier_of(result: Investigation) -> str:
    """Return the application id an investigation narrowed to, if it did."""
    if result.scope != "application" or not result.applications:
        return ""
    return str(result.applications[0].app_id)


CONFIG_EPILOG = """
\b
Examples:

  entrascope config path                    where configuration is read from
  entrascope config export ~/.entrascope    take a copy to edit
  entrascope config show endpoints.yaml     read one file
"""


@cli.group(cls=GuidedGroup, epilog=CONFIG_EPILOG, invoke_without_command=True)
def config_group() -> None:
    """Find, read and take a copy of the configuration.

    Every endpoint, table name, retry value, error code and documentation link
    lives in configuration rather than in code. An installed entrascope carries
    its own copy inside the package, which is awkward to edit and is replaced
    on upgrade, so take a copy and point ENTRASCOPE_CONFIG_DIR at it.
    """


config_group.command_class = GlobalOptionCommand


@config_group.command("path")
@click.pass_context
@handled
def config_path(context: click.Context) -> None:
    """Say where configuration is being read from, and where else was looked."""
    settings = settings_of(context)
    active: Config = settings["config"]
    rows = [
        {
            "directory": str(candidate),
            "what_it_is": describe_directory(candidate),
            "files": len(sorted(candidate.glob("*.yaml"))) if candidate.is_dir() else 0,
            "in_use": candidate == active.root,
        }
        for candidate in candidate_directories()
    ]
    show(
        rows,
        settings,
        "Configuration",
        ("directory", "what_it_is", "files", "in_use"),
        "places",
    )
    if active.defaults_root is not None:
        emit(
            f"\nYours at {active.root} is layered over the defaults at "
            f"{active.defaults_root}. Anything you have not changed comes from "
            "there, so an upgrade that adds a setting is picked up on its own."
        )
    elif active.root == packaged_config_dir():
        emit(
            "\nThis is the copy inside the package, which is replaced whenever "
            "entrascope is upgraded. Run entrascope config export to take a "
            "copy that is not."
        )


def describe_directory(candidate: Path) -> str:
    """Say what a candidate directory is, so the order makes sense."""
    if candidate == user_config_dir():
        return "yours, layered over the defaults, survives an upgrade"
    if candidate == packaged_config_dir():
        return "shipped defaults, replaced on upgrade"
    if candidate == repository_config_dir():
        return "a development checkout"
    return "named explicitly, used as it stands"


@config_group.command("export")
@click.argument(
    "directory", type=click.Path(file_okay=False, path_type=Path), required=False
)
@click.option("--force", is_flag=True, help="Overwrite files that are already there.")
@click.option(
    "--use",
    is_flag=True,
    help="Write to your own configuration directory, where entrascope reads it "
    "automatically, rather than to the downloads folder.",
)
@click.option(
    "--only",
    "only",
    multiple=True,
    help="Copy just these files, for example --only credentials.yaml. A "
    "directory holding only what you changed is easier to carry forward.",
)
@click.pass_context
@handled
def config_export(
    context: click.Context,
    directory: Path | None,
    force: bool,
    use: bool,
    only: tuple[str, ...],
) -> None:
    """Copy the configuration somewhere you can edit it.

    With no directory it copies to the downloads folder, where a file is easy
    to find and open. That copy is for reading and editing and does not take
    effect on its own. Pass --use to write it to your own configuration
    directory instead, which is outside the package, is used automatically, and
    is never touched when entrascope is upgraded. Anything left out of that
    directory comes from the shipped defaults, so a release that adds a setting
    is picked up without you doing anything.

        entrascope config export                  a copy to read, in Downloads
        entrascope config export --use            put it where it takes effect
        entrascope config export ~/somewhere      or anywhere you name
    """
    settings = settings_of(context)
    active: Config = settings["config"]
    target = directory or (user_config_dir() if use else downloads_dir())
    source = active.defaults_root or active.root
    written = copy_configuration(source, target, force=force, only=only)
    emit(f"Copied {len(written)} files from {source} to {target}.")
    for path in written:
        emit(f"  {path}")
    if use:
        emit("That directory is used automatically and survives an upgrade.")
    elif directory is None:
        emit(
            "This copy is for reading. To make it the configuration in force, "
            "run entrascope config export --use, or move it to "
            f"{user_config_dir()}."
        )
    else:
        emit(f"Use it with:  export ENTRASCOPE_CONFIG_DIR={target}")


@config_group.command("show")
@click.argument("name", required=False)
@click.pass_context
@handled
def config_show(context: click.Context, name: str | None = None) -> None:
    """Show the configuration in use, or one file of it.

    With no file named, this is every setting entrascope is actually running
    with, together with the full paths it was read from.
    """
    settings = settings_of(context)
    active: Config = settings["config"]
    if not name:
        show_yaml(effective(active), active, settings.get("output", "yaml"))
        return
    path = (active.root / name).resolve()
    if not path.is_relative_to(active.root.resolve()) or not path.is_file():
        available = sorted(item.name for item in active.root.glob("*.yaml"))
        raise ConfigError(
            f"No configuration file named {name}. Available: {available}, and "
            "the KQL templates under kql."
        )
    emit(f"# {path}")
    emit(read_text_file(path))


def copy_configuration(
    source: Path, destination: Path, *, force: bool, only: Sequence[str] = ()
) -> list[Path]:
    """Copy a configuration directory, refusing to overwrite without being told.

    Everything is checked before anything is written. Refusing halfway leaves a
    directory holding some of one release and some of another, which is worse
    than refusing before it started.
    """
    wanted = set(only)
    pairs = [
        (item, destination / item.relative_to(source))
        for item in sorted(source.rglob("*"))
        if not item.is_dir() and (not wanted or item.name in wanted)
    ]
    if not force:
        existing = [str(target) for _, target in pairs if target.exists()]
        if existing:
            raise ConfigError(
                f"{existing[0]} is already there, along with {len(existing) - 1} "
                "other files. Pass --force to overwrite, or choose an empty "
                "directory."
                if len(existing) > 1
                else f"{existing[0]} is already there. Pass --force to "
                "overwrite, or choose an empty directory."
            )
    written: list[Path] = []
    for item, target in pairs:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(item.read_bytes())
        written.append(target)
    return written


@cli.command("upgrade", cls=GlobalOptionCommand)
@click.option(
    "--check",
    "check_only",
    is_flag=True,
    help="Say whether a newer version exists and how this copy would be "
    "upgraded, without changing anything.",
)
@click.option(
    "--break-system-packages",
    is_flag=True,
    help="Upgrade into a Python that is managed by something other than pip. "
    "This can break the tooling that owns it, so it is never done without "
    "being asked for.",
)
@click.option("--dry-run", is_flag=True, help="Show the command without running it.")
@click.pass_context
@handled
def upgrade(
    context: click.Context,
    check_only: bool,
    break_system_packages: bool,
    dry_run: bool,
) -> None:
    """Upgrade entrascope, the way this copy was installed.

    How a package is upgraded depends on how it was installed, and getting that
    wrong on a system Python is worse than not offering it. This works out
    which it is and uses the right command, through this interpreter rather
    than whichever pip happens to be on the path.
    """
    settings = settings_of(context)
    config: Config = settings["config"]
    output: OutputFormat = settings.get("output", "table")
    report = describe_installation(config)
    published = latest_release(config, force=True)
    release = published if published and published.newer_than(__version__) else None
    report["latest_version"] = (
        published.version if published else report["running_version"]
    )
    report["upgrade_available"] = bool(release)
    report["release_notes"] = published.url if published else None
    # The files, always, because somebody whose Python is managed by something
    # else cannot run the upgrade and can still fetch the wheel, and somebody
    # behind a proxy that blocks the index needs the address to hand.
    report["files"] = list(published.files) if published else []

    if check_only or dry_run:
        # One record reads as a list of fields, not as a table one column wide
        # for each thing it has to say.
        if output in ("json", "yaml", "plain"):
            show_yaml(report, config, output)
        else:
            emit(render_record(report, config, title="entrascope"))
        return

    if not release:
        emit(f"entrascope {report['running_version']} is the newest version.")
        return

    emit(f"Upgrading from {report['running_version']} to {release.version}.")
    emit(f"Release notes: {release.url}")
    for address in release.files:
        emit(f"  {address}")
    command, output_text = run_upgrade(
        config, break_system_packages=break_system_packages
    )
    emit(f"Ran: {' '.join(command)}")
    if output_text.strip():
        # An index URL can carry credentials, and the installer echoes it.
        emit(str(redact_with_config(tail(output_text, lines=6), config)))
    emit(f"Now run entrascope --version to confirm. Notes: {release.url}")


@cli.command("whoami", cls=GlobalOptionCommand)
@click.option(
    "--no-policies",
    is_flag=True,
    help="Skip the conditional access policies, which need Policy.Read.All.",
)
@click.pass_context
@handled
def whoami_command(context: click.Context, no_policies: bool) -> None:
    """Show which tenant and identity entrascope is querying as, and its limits.

    Reports the tenant by name and identifier, the tenants this identity can
    reach, the identity itself, the application permissions and delegated
    scopes the token actually carries, the directory roles held, the
    administrative units that bound them, and the conditional access policies
    in force.

    Start here when a result is not what you expected. The identity a tool
    authenticates as is rarely the one anybody had in mind.
    """
    settings = settings_of(context)
    config: Config = settings["config"]
    auth_context, credential = resolve_auth(
        config, settings.get("auth"), named=settings.get("credential_file")
    )
    session = graph_session_for(config, credential)
    try:
        report = run_whoami(
            session,
            config,
            credential,
            auth_context,
            with_policies=not no_policies,
        )
    finally:
        session.close()
    output: OutputFormat = settings.get("output", "table")
    if output == "plain":
        emit(yaml_text(report, config))
        return
    show_yaml(report, config, output)


# framework contract: click decides how a token becomes a command through a
# Group method, so accepting the name of an application where a subcommand is
# expected means overriding it. No logic beyond the lookup.
class InspectGroup(AliasGroup):
    """A group that also answers to the name of an application, with the
    global options on the group as well as on its subcommands.

    Listing applications and reading one of them are the same question asked
    at two depths, so they are one command. Anything that is not a subcommand
    is taken to be the application somebody wants to see, which keeps
    ``entrascope inspect saml2`` meaning what it has always meant.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # This was a command before it was a group, and it was invoked as
        # "entrascope inspect --auth file" every day. That must keep working.
        self.params.extend(global_options())

    def invoke(self, ctx: click.Context) -> Any:
        """Apply any global option given on the group, then run.

        With no subcommand the callback offers the list itself, so unlike other
        groups this one does not go on to offer its commands.
        """
        apply_overrides(ctx, pop_global_options(ctx))
        return click.Group.invoke(self, ctx)

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        """Resolve a subcommand, or fall back to reading one application."""
        name = args[0] if args else ""
        if name and not name.startswith("-") and self.get_command(ctx, name) is None:
            return "app", self.get_command(ctx, "app"), args
        return super().resolve_command(ctx, args)


@cli.group(
    "inspect", cls=InspectGroup, epilog=INSPECT_EPILOG, invoke_without_command=True
)
@click.option("--type", "kinds", multiple=True, help=TYPE_HELP)
@click.option("--all", "everything", is_flag=True, help=EVERYTHING_HELP)
@click.pass_context
@handled
def inspect_group(
    context: click.Context,
    kinds: tuple[str, ...],
    everything: bool,
) -> None:
    """Look at applications: the whole list, or one of them in full.

    An application registration is the definition you create in Entra. An
    enterprise application is the service principal, the instance of that
    definition inside a tenant. A failure can come from either, so both are
    listed separately and both are shown when one application is read.

    With no subcommand and a terminal to draw on, the list is offered to choose
    from. Naming an application reads that one: part of a display name, an
    application id or an object id.

    \b
        entrascope inspect                          choose from the list
        entrascope inspect saml2                    by name
        entrascope inspect d6bdb5c4-1722-4c63-930f-fa264d4778bc
        entrascope inspect --type managed-identity  narrowed by type
    """
    if context.invoked_subcommand is not None:
        return
    if not available():
        # Nothing to draw the list on, so say what the command can do rather
        # than reading the whole directory and then finding nobody to ask.
        emit(context.get_help())
        return
    settings = settings_of(context)
    output: OutputFormat = settings.get("output", "table")
    with graph_session(settings) as (config, session, token):
        # Read the directory once and stay in the chooser, because looking at
        # one application is almost never the whole question.
        with working("Reading applications"):
            catalogue = read_catalogue(session, config, token, everything=everything)
        browse(catalogue, session, config, token, list(kinds), output)


# Every command in this group accepts the global options too, so that nobody
# has to remember which side of the subcommand they go on.
inspect_group.command_class = GlobalOptionCommand


@inspect_group.command("app")
@click.argument("target", required=False, default="")
@click.option("--type", "kinds", multiple=True, help=TYPE_HELP)
@click.option("--all", "everything", is_flag=True, help=EVERYTHING_HELP)
@click.pass_context
@handled
def inspect_command(
    context: click.Context,
    target: str,
    kinds: tuple[str, ...],
    everything: bool,
) -> None:
    """Show everything about one application, as YAML.

    Both objects are shown together, the registration and the enterprise
    application, because a failure can come from either: the scopes it exposes,
    the roles it defines, what it asked for against what was actually
    consented, every URL it is registered with, its credentials and their
    expiry, and its single sign on configuration.
    """
    settings = settings_of(context)
    output: OutputFormat = settings.get("output", "table")
    with graph_session(settings) as (config, session, token):
        if target:
            with working(f"Looking for {target} and reading it in full"):
                report = run_inspect(
                    session, config, token, target=target, kinds=list(kinds)
                )
            write_report(report, config, output)
            return
        # No target. Read the directory once and stay in the chooser, because
        # looking at one application is almost never the whole question.
        with working("Reading applications"):
            catalogue = read_catalogue(session, config, token, everything=everything)
        browse(catalogue, session, config, token, list(kinds), output)


def write_report(
    report: Mapping[str, Any], config: Config, output: OutputFormat
) -> None:
    """Write one inspection in the requested form."""
    if output == "plain":
        emit(yaml_text(report, config))
        return
    show_yaml(report, config, output)


def browse(
    catalogue: Catalogue,
    session: Session,
    config: Config,
    token: Callable[[], str],
    kinds: list[str],
    output: OutputFormat,
) -> None:
    """Offer the list, show what is chosen, and come back to the list.

    Reading one application and being dropped back at the shell is rarely what
    somebody wanted. The chooser returns until it is closed.
    """
    lines = catalogue.lines()
    if not lines:
        raise ConfigError("There are no applications this identity can see.")
    if catalogue.hidden:
        emit_error(
            "Kept out of the list: " + ", ".join(catalogue.hidden) + ". Pass --all "
            "to include them."
        )
    opened = 0
    while True:
        picked = choose(list(lines), title="Applications", **palette(config))
        if picked is None:
            # Escape means go back, not stop. With a terminal there is a menu
            # to go back to, and only without one is there nothing to say but
            # how the list could have been narrowed.
            if opened == 0 and not available():
                raise ConfigError(no_choice_made(len(lines)))
            return
        with working("Reading that application in full"):
            report = run_inspect(
                session, config, token, target=picked, kinds=kinds, catalogue=catalogue
            )
        write_report(report, config, output)
        opened += 1
        if not available():
            return
        if after_viewing(report, config) == "quit":
            return


#: What somebody might want once an application has been read. A question with
#: only yes and no for answers cannot offer any of this.
AFTER_VIEWING: tuple[tuple[str, str], ...] = (
    ("list", "back to the list"),
    ("save", "save this application to a YAML file"),
    ("quit", "leave"),
)


def after_viewing(report: Mapping[str, Any], config: Config) -> str:
    """Offer what to do next and carry it out, returning what was chosen."""
    emit("")
    chosen = choose(
        [Choice(key=key, label=label) for key, label in AFTER_VIEWING],
        title="Next",
        **palette(config),
    )
    if chosen == "save":
        save_report(report, config)
        return "list"
    return "quit" if chosen == "quit" else "list"


def save_report(report: Mapping[str, Any], config: Config) -> None:
    """Write one inspection to a YAML file named after the application."""
    identity = report.get("identity") or {}
    name = str(identity.get("display_name") or "application")
    path = free_name(safe_name(name, "application"))
    path.write_text(yaml_text(report, config), encoding="utf-8")
    emit(f"Saved to {path}")


def safe_name(name: str, fallback: str) -> Path:
    """Return a file name made from a display name.

    A display name is somebody else's text. It may hold a slash, which would
    make this a path rather than a name, so only letters, digits and a few
    harmless characters survive.
    """
    kept = "".join(
        character if character.isalnum() or character in "-_." else "-"
        for character in name.strip()
    ).strip("-.")
    return Path(f"{kept or fallback}.yaml")


def free_name(path: Path) -> Path:
    """Return a name nothing is using, numbering it if the first one is taken.

    Saving is meant to keep something, and quietly writing over what somebody
    saved a minute ago is the opposite of keeping it.
    """
    candidate = path.resolve()
    for number in range(2, 100):
        if not candidate.exists():
            return candidate
        candidate = path.with_name(f"{path.stem}-{number}{path.suffix}").resolve()
    raise ConfigError(
        f"There are already ninety nine files named like {path.name} here. "
        "Move some of them, or run this from another directory."
    )


def no_choice_made(total: int) -> str:
    """Explain how to name an application when the chooser was not used."""
    return (
        "Nothing chosen. Name an application instead: part of a display name, "
        f"an application id or an object id. There are {total} to choose from, "
        "and entrascope discover applications lists them."
    )


@cli.command(cls=GlobalOptionCommand)
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
    results = run_checks(config, requested=auth, named=settings.get("credential_file"))
    show_checks(results, config, output)
    raise SystemExit(exit_code_for_checks(results))


@inspect_group.command("applications")
@click.option("--filter", "filter_expression", default=None, help=FILTER_HELP)
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
    with graph_session(settings) as (config, session, token):
        rows = discover_applications(
            session,
            config,
            None if no_details else token,
            filter_expression=filter_expression,
            with_details=not no_details,
        )
    rows = narrowed(rows, app_selector, application_type, matches)
    if expiring:
        rows = tuple(row for row in rows if row.expiring())
    show(
        rows,
        settings,
        "Application registrations",
        APPLICATION_COLUMNS,
        "application registrations",
        APPLICATION_TABLE_COLUMNS,
    )


@inspect_group.command("enterprise-apps")
@click.option("--filter", "filter_expression", default=None, help=FILTER_HELP)
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
    with graph_session(settings) as (config, session, token):
        rows = discover_service_principals(
            session,
            config,
            None if no_details else token,
            filter_expression=filter_expression,
            with_details=not no_details,
        )
    if not include_first_party:
        rows = tuple(row for row in rows if not is_first_party(row, config))
    rows = narrowed(rows, app_selector, application_type, matches_principal)
    show(
        rows,
        settings,
        "Enterprise applications",
        SERVICE_PRINCIPAL_COLUMNS,
        "enterprise applications",
        SERVICE_PRINCIPAL_TABLE_COLUMNS,
    )


@inspect_group.command("gallery")
@click.argument("term", required=False, default="")
@click.option("--limit", type=int, default=None, help=LIMIT_HELP)
@click.pass_context
@handled
def discover_gallery(context: click.Context, term: str, limit: int | None) -> None:
    """Search the gallery of applications that can be added to the tenant.

    This is the list the portal searches when you add an enterprise
    application, so it answers whether something is available ready made, and
    which single sign on modes it supports.

        entrascope discover gallery saml
        entrascope discover gallery "amazon web services"
    """
    settings = settings_of(context)
    with graph_session(settings) as (config, session, _):
        rows, note = search_gallery(session, config, term, limit or 50)
    if note:
        emit_error(note)
    projected = [
        {
            "display_name": row.get("displayName"),
            "publisher": row.get("publisher"),
            "categories": row.get("categories"),
            "single_sign_on_modes": row.get("supportedSingleSignOnModes"),
            "id": row.get("id"),
        }
        for row in rows
    ]
    show(
        projected,
        settings,
        f"Gallery applications matching {term}" if term else "Gallery applications",
        ("display_name", "publisher", "single_sign_on_modes", "categories", "id"),
        "gallery applications",
        ("display_name", "publisher", "single_sign_on_modes"),
    )


@cli.group(cls=GuidedGroup, epilog=LOGS_EPILOG, invoke_without_command=True)
def logs() -> None:
    """Read Entra and Azure Monitor logs.

    Entra directory operations do not appear in the Azure subscription activity
    log. They are in the Entra audit logs, which is what these commands read.
    """


# Every command in this group accepts the global options too, so that nobody
# has to remember which side of the subcommand they go on.
logs.command_class = GlobalOptionCommand


@logs.command("audit")
@route_options
@click.option("--category", default=None, help=CATEGORY_HELP)
@click.option("--hours", type=int, default=None, help=HOURS_HELP)
@click.option("--limit", type=int, default=None, help=LIMIT_HELP)
@click.option("--app", "app_selector", default="", help=APP_SELECTOR_HELP)
@click.option("--failures-only", is_flag=True, help="Show only operations that failed.")
@click.option("--pick", is_flag=True, help=PICK_HELP)
@click.pass_context
@handled
def logs_audit(
    context: click.Context,
    route: str,
    workspace: str | None,
    category: str | None,
    hours: int | None,
    limit: int | None,
    app_selector: str,
    failures_only: bool,
    pick: bool,
) -> None:
    """Read directory changes recorded in the Entra audit log.

    Application management by default, which is where changes to application
    registrations and enterprise applications are recorded. Pass --category to
    read another, or --category all for every one. Run entrascope logs
    categories for the list.
    """
    settings = settings_of(context)
    if route == "monitor":
        config, client = logs_client(settings)
        rows = query_audit_monitor(
            client,
            config,
            require_workspace(workspace, config),
            category=category,
            target=app_selector,
            lookback_hours=hours,
            row_limit=limit,
        )
    else:
        with graph_session(settings) as (config, session, _):
            rows = query_audit_graph(
                session,
                config,
                category=category,
                target=app_selector,
                lookback_hours=hours,
                top=limit,
            )
    failures = set(config.fields.findings.audit_failure_results)
    if failures_only:
        rows = tuple(row for row in rows if row.result.lower() in failures)
    # The reason is only worth a column when something failed, and then it is
    # the whole point of looking.
    anything_failed = any(row.result.lower() in failures for row in rows)
    table_columns = AUDIT_FAILURE_COLUMNS if anything_failed else AUDIT_TABLE_COLUMNS
    if pick:
        pick_one(rows, settings, table_columns)
        return
    show(
        rows,
        settings,
        audit_title(config, category),
        AUDIT_COLUMNS,
        "audit events",
        table_columns,
    )
    if app_selector and route == "graph" and not looks_like_identifier(app_selector):
        # Graph can match an audit event against an object id and not against a
        # name, so a name is matched here, over the rows that arrived. Somebody
        # seeing nothing should know whether that means nothing happened or
        # only that nothing among the newest rows did.
        emit_error(
            f"{app_selector!r} is a name, and Microsoft Graph can only narrow "
            "an audit query by object id, so the name was matched over the "
            f"newest {limit or config.tables.defaults.row_limit} events rather "
            "than over the whole period. Pass the object id to narrow at the "
            "service, or raise --limit."
        )
    if anything_failed and not failures_only:
        emit_error(
            "Something failed above. Narrow with --failures-only, open one "
            "line with --pick, or run entrascope investigate for the cause."
        )


@logs.command("signins")
@click.option(
    "--kind",
    default="interactive",
    help="Which sign in kind to read. Run entrascope logs kinds for the list.",
)
@route_options
@click.option("--app", "app_id", default="", help=APP_SELECTOR_HELP)
@click.option("--failures-only", is_flag=True, help="Show only sign ins that failed.")
@click.option("--pick", is_flag=True, help=PICK_HELP)
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
    pick: bool,
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
            require_workspace(workspace, config),
            kind=kind,
            app_id=app_id,
            failures_only=failures_only,
            lookback_hours=hours,
            row_limit=limit,
        )
    else:
        with graph_session(settings) as (config, session, _):
            rows = query_sign_ins_graph(
                session,
                config,
                kind=kind,
                app_id=app_id or None,
                failures_only=failures_only,
                lookback_hours=hours,
                top=limit,
            )
    if pick:
        pick_one(rows, settings, SIGN_IN_TABLE_COLUMNS)
        return
    show(
        rows,
        settings,
        f"{kind} sign ins",
        SIGN_IN_COLUMNS,
        "sign ins",
        SIGN_IN_TABLE_COLUMNS,
    )


@logs.command("graph-activity")
@click.option("--workspace", default=None, help=GRAPH_ACTIVITY_WORKSPACE_HELP)
@click.option("--app", "app_id", default="", help=APP_SELECTOR_HELP)
@click.option("--pick", is_flag=True, help=PICK_HELP)
@click.option("--hours", type=int, default=None, help=HOURS_HELP)
@click.option("--limit", type=int, default=None, help=LIMIT_HELP)
@click.pass_context
@handled
def logs_graph_activity(
    context: click.Context,
    workspace: str | None,
    app_id: str,
    pick: bool,
    hours: int | None,
    limit: int | None,
) -> None:
    """Read Microsoft Graph requests made against the tenant.

    This source exists only through Azure Monitor, and needs the
    MicrosoftGraphActivityLogs diagnostic category and a P1 or P2 licence.
    There is no graph route, because this is the log of the Graph route itself.
    """
    settings = settings_of(context)
    config, client = logs_client(settings)
    rows = query_graph_activity(
        client,
        config,
        require_workspace(workspace, config, "graph-activity"),
        app_id=app_id,
        lookback_hours=hours,
        row_limit=limit,
    )
    if pick:
        pick_one(rows, settings, GRAPH_ACTIVITY_COLUMNS)
        return
    show(rows, settings, "Microsoft Graph activity", GRAPH_ACTIVITY_COLUMNS, "requests")


@logs.command("categories")
@click.argument("category", required=False, default="")
@click.pass_context
@handled
def logs_categories(context: click.Context, category: str) -> None:
    """List the audit categories, or describe one of them.

    Each is read with logs audit --category. Application management is the
    default, because it is where changes to applications are recorded.
    """
    settings = settings_of(context)
    config: Config = settings["config"]
    default = config.tables.default_audit_category
    rows = [
        {
            "category": name,
            "graph_value": value or "every category",
            "default": name == default,
        }
        for name, value in sorted(config.tables.audit_categories.items())
        if not category or category == name
    ]
    if category and not rows:
        known = ", ".join(sorted(config.tables.audit_categories))
        raise ConfigError(
            f"No audit category named {category}. Known categories: {known}."
        )
    columns = ("category", "graph_value", "default")
    show(rows, settings, "Audit categories", columns, "categories")


@logs.command("kinds")
@click.argument("kind", required=False, default="")
@click.pass_context
@handled
def logs_kinds(context: click.Context, kind: str) -> None:
    """Describe the sign in kinds, or one of them.

    Every kind is read with logs signins --kind. Name one here to see what it
    covers and what it needs.
    """
    settings = settings_of(context)
    config: Config = settings["config"]
    categories = {entry.name: entry for entry in config.tables.diagnostic_categories}
    rows = [
        {
            "kind": name,
            "covers": categories[entry.diagnostic_category].description
            if entry.diagnostic_category in categories
            else "",
            "diagnostic_category": entry.diagnostic_category,
            "minimum_licence": categories[entry.diagnostic_category].minimum_licence
            if entry.diagnostic_category in categories
            else "",
            "graph_endpoint": "beta" if entry.graph_beta else "v1.0",
        }
        for name, entry in sorted(config.tables.sign_in_kinds.items())
        if not kind or kind == name
    ]
    if kind and not rows:
        known = ", ".join(sorted(config.tables.sign_in_kinds))
        raise ConfigError(f"No sign in kind named {kind}. Known kinds: {known}.")
    columns = (
        "kind",
        "covers",
        "diagnostic_category",
        "minimum_licence",
        "graph_endpoint",
    )
    show(
        rows,
        settings,
        "Sign in kinds",
        columns,
        "kinds",
        ("kind", "diagnostic_category", "minimum_licence", "covers"),
    )


@cli.group(cls=GuidedGroup, epilog=ERRORS_EPILOG, invoke_without_command=True)
def errors() -> None:
    """Explain authentication and authorisation error codes."""


# Every command in this group accepts the global options too, so that nobody
# has to remember which side of the subcommand they go on.
errors.command_class = GlobalOptionCommand


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


@cli.group(cls=GuidedGroup, epilog=SERVE_EPILOG, invoke_without_command=True)
def serve() -> None:
    """Run entrascope as a Model Context Protocol server."""


# Every command in this group accepts the global options too, so that nobody
# has to remember which side of the subcommand they go on.
serve.command_class = GlobalOptionCommand


@serve.command("stdio")
@click.pass_context
@handled
def serve_stdio(context: click.Context) -> None:
    """Serve the tools over stdio, for an assistant running on this machine.

    stdio has no OAuth, so credentials come from the environment or the
    credential file exactly as they do for every other command. Standard output
    carries the protocol, so logging goes to standard error as JSON lines.
    """
    server_module = import_server("mcp_stdio")
    settings = settings_of(context)
    config: Config = settings["config"]
    emit_error("Serving over stdio. Press control C to stop.")
    server_module.run(server_module.build_server(config, settings.get("auth")))


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
    server_module = import_server("mcp_http")
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
    listening = config.server.transport
    emit(
        f"Serving over Streamable HTTP on {listening.host}:{listening.port}"
        f"{listening.path}. Press control C to stop."
    )
    server_module.run(config)


def main() -> None:
    """Console script entry point."""
    cli(obj={})
