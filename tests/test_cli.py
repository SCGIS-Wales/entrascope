"""Command line surface tests."""

from __future__ import annotations

from click.testing import CliRunner

from entrascope import __version__
from entrascope.cli import cli


def test_cli_help() -> None:
    """The root help lists the command groups."""
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    for group in ("discover", "logs", "errors"):
        assert group in result.output


def test_cli_version() -> None:
    """The version option reports the package version."""
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_states_activity_log_caveat() -> None:
    """The root help carries the Azure activity log caveat."""
    result = CliRunner().invoke(cli, ["--help"])
    normalised = " ".join(result.output.lower().split())
    assert "do not appear in the azure subscription activity log" in normalised
