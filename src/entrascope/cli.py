"""Command line surface.

The click group is the only public entry point. Every command delegates to a
free function in another module and renders through :mod:`entrascope.render`.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any

import click

from entrascope import __version__
from entrascope.config import Config, load_config
from entrascope.doctor import run_checks
from entrascope.logger import bind_context, configure_logging, new_correlation_id
from entrascope.models import (
    AUTH_SOURCE_ORDER,
    ApiCallError,
    AuthSource,
    ConfigError,
    CredentialError,
)
from entrascope.render import (
    EXIT_API,
    EXIT_CONFIG,
    EXIT_CREDENTIALS,
    OUTPUT_FORMATS,
    OutputFormat,
    emit,
    emit_error,
    exit_code_for_checks,
    render_checks,
)

#: Key under which the shared settings are held on the click context.
SETTINGS = "settings"


def build_settings(
    config_dir: Path | None, auth: str | None, output: str, verbose: bool
) -> dict[str, Any]:
    """Load configuration and prepare the shared settings for every command."""
    config = load_config(config_dir)
    configure_logging(config, surface="cli", level="DEBUG" if verbose else None)
    new_correlation_id()
    if auth:
        bind_context(auth_source=auth)
    return {"config": config, "auth": auth, "output": output}


def settings_of(context: click.Context) -> dict[str, Any]:
    """Return the shared settings from the click context."""
    values = context.obj or {}
    result = values.get(SETTINGS)
    return dict(result) if isinstance(result, dict) else {}


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


@cli.group()
def logs() -> None:
    """Interrogate Entra and Azure Monitor logs."""


@cli.group()
def errors() -> None:
    """Explain authentication and authorisation error codes."""


def main() -> None:
    """Console script entry point."""
    cli(obj={})
