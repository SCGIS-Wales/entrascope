"""Command line surface.

The click group is the only public entry point. Every command delegates to a
free function in another module and renders through :mod:`entrascope.render`.
"""

from __future__ import annotations

import click

from entrascope import __version__


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="entrascope")
def cli() -> None:
    """Diagnose Entra ID and Azure application authentication failures.

    Entra directory operations do not appear in the Azure subscription
    activity log. They are recorded in the Entra audit logs, which this tool
    reads through Microsoft Graph and through Azure Monitor.
    """


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
    cli()
