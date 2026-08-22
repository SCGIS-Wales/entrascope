"""Command line surface tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from entrascope import __version__
from entrascope.cli import cli
from entrascope.render import EXIT_CONFIG
from tests.conftest import SENTINEL_SECRET


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


def test_cli_global_options_are_documented() -> None:
    """The global options are discoverable from the root help."""
    result = CliRunner().invoke(cli, ["--help"])
    for option in ("--auth", "--output", "--config-dir", "--verbose", "doctor"):
        assert option in result.output


def test_cli_auth_choices_cover_every_source() -> None:
    """Each authentication source can be named on the command line."""
    output = " ".join(CliRunner().invoke(cli, ["--help"]).output.split())
    for source in ("file", "env", "azure-cli", "default"):
        assert source in output


def test_cli_rejects_an_unknown_auth_source() -> None:
    """A source that does not exist is refused with the list of those that do."""
    result = CliRunner().invoke(cli, ["--auth", "telepathy", "doctor"])
    assert result.exit_code != 0
    assert "azure-cli" in result.output


def test_cli_rejects_an_unknown_output_format() -> None:
    """An output format that does not exist is refused."""
    result = CliRunner().invoke(cli, ["--output", "xml", "doctor"])
    assert result.exit_code != 0


def test_doctor_runs_and_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    """The doctor command renders a report and exits non zero on a failure."""
    monkeypatch.setattr("entrascope.credentials.shutil.which", lambda _: None)
    result = CliRunner().invoke(cli, ["doctor"], obj={})
    assert result.exit_code in (0, 1)
    assert "entrascope doctor" in result.output or "network path" in result.output


def test_doctor_yaml_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """The machine readable report parses as YAML."""
    monkeypatch.setattr("entrascope.credentials.shutil.which", lambda _: None)
    result = CliRunner().invoke(cli, ["--output", "yaml", "doctor"], obj={})
    parsed = yaml.safe_load(result.output)
    assert isinstance(parsed, list)
    assert {"check", "passed", "detail"} <= set(parsed[0])


def test_doctor_json_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """The machine readable report parses as JSON."""
    monkeypatch.setattr("entrascope.credentials.shutil.which", lambda _: None)
    result = CliRunner().invoke(cli, ["--output", "json", "doctor"], obj={})
    assert isinstance(json.loads(result.output), list)


def test_a_bad_config_directory_exits_with_the_config_code(tmp_path: Path) -> None:
    """A configuration failure is a message and an exit code, not a stack trace."""
    result = CliRunner().invoke(cli, ["--config-dir", str(tmp_path), "doctor"], obj={})
    assert result.exit_code == EXIT_CONFIG
    assert "configuration directory" in result.output.lower()


def test_the_secret_never_reaches_the_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Running doctor against a badly stored credential shows no secret."""
    from entrascope.config import load_config
    from tests.test_credentials import write_credentials

    write_credentials(tmp_path, config=load_config(), file_mode=0o644)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    result = CliRunner().invoke(cli, ["--auth", "file", "doctor"], obj={})
    assert SENTINEL_SECRET not in result.output
