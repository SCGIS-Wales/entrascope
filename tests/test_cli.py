"""Command line surface tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import responses
import yaml
from click.testing import CliRunner

from entrascope import __version__
from entrascope.cli import cli
from entrascope.render import EXIT_API, EXIT_CHECKS_FAILED, EXIT_CONFIG
from tests.conftest import SENTINEL_SECRET, load_fixture


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
    parsed = yaml.safe_load(result.stdout)
    assert isinstance(parsed, list)
    assert {"check", "passed", "detail"} <= set(parsed[0])


def test_doctor_json_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """The machine readable report parses as JSON."""
    monkeypatch.setattr("entrascope.credentials.shutil.which", lambda _: None)
    result = CliRunner().invoke(cli, ["--output", "json", "doctor"], obj={})
    assert isinstance(json.loads(result.stdout), list)


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


ROOT = "https://graph.microsoft.com/v1.0"


@pytest.fixture
def authenticated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Make the file source resolve to a credential that yields a fixed token."""
    from entrascope.config import load_config
    from tests.test_credentials import write_credentials

    write_credentials(tmp_path, config=load_config())
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

    # framework contract: azure-core defines the credential and token shapes.
    class Token:
        token = "token"
        expires_on = 4_102_444_800

    class Credential:
        def get_token(self, *scopes: str, **kwargs: object) -> object:
            return Token()

    monkeypatch.setattr(
        "entrascope.credentials.build_client_secret_credential",
        lambda credential, verify=True: Credential(),
    )


def run(arguments: list[str]) -> Any:
    """Invoke the command line with a fresh context."""
    return CliRunner().invoke(cli, arguments, obj={})


@responses.activate
def test_cli_discover_apps(authenticated: None) -> None:
    """Discovery renders a table of application registrations."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json=load_fixture("applications"),
        status=200,
    )
    result = run(["--auth", "file", "discover", "apps", "--no-details"])
    assert result.exit_code == 0, result.output
    assert "Confidential web application" in result.output
    assert "single-page-application" in result.output


@responses.activate
def test_cli_discover_apps_filters_by_type(authenticated: None) -> None:
    """The type option narrows the result to one classification."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json=load_fixture("applications"),
        status=200,
    )
    result = run(
        [
            "--auth",
            "file",
            "discover",
            "apps",
            "--no-details",
            "--type",
            "single-page-application",
        ]
    )
    assert "Single page application" in result.output
    assert "Native desktop client" not in result.output


@responses.activate
def test_cli_discover_apps_shows_only_expiring(authenticated: None) -> None:
    """The expiring flag answers the question an engineer usually has."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json=load_fixture("applications"),
        status=200,
    )
    result = run(["--auth", "file", "discover", "apps", "--no-details", "--expiring"])
    assert "Confidential web application" in result.output
    assert "Single page application" not in result.output


@responses.activate
def test_cli_discover_service_principals(authenticated: None) -> None:
    """Enterprise application discovery renders every type."""
    responses.add(
        responses.GET,
        f"{ROOT}/servicePrincipals",
        json=load_fixture("service_principals"),
        status=200,
    )
    result = run(["--auth", "file", "discover", "sps", "--no-details"])
    assert result.exit_code == 0, result.output
    assert "managed-identity" in result.output
    assert "saml-gallery" in result.output


@responses.activate
def test_cli_logs_audit(authenticated: None) -> None:
    """Audit events render, filtered to application management."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/directoryAudits",
        json=load_fixture("audit_events"),
        status=200,
    )
    result = run(["--auth", "file", "logs", "audit"])
    assert result.exit_code == 0, result.output
    assert "Update application" in result.output


@responses.activate
def test_cli_logs_signins_failures_only(authenticated: None) -> None:
    """Failures only is what an engineer diagnosing a problem asks for."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/signIns",
        json=load_fixture("sign_ins"),
        status=200,
    )
    result = run(["--auth", "file", "logs", "signins", "--failures-only"])
    assert result.exit_code == 0, result.output
    assert "50011" in result.output


def test_cli_logs_monitor_route_needs_a_workspace(authenticated: None) -> None:
    """The Azure Monitor route explains that it needs a workspace."""
    result = run(["--auth", "file", "logs", "audit", "--route", "monitor"])
    assert result.exit_code == EXIT_CONFIG
    assert "--workspace" in result.output


def test_cli_logs_kinds_lists_the_sign_in_kinds() -> None:
    """The sign in kinds are discoverable without credentials."""
    result = run(["logs", "kinds"])
    assert result.exit_code == 0, result.output
    assert "service-principal" in result.output
    assert "ServicePrincipalSignInLogs" in result.output


def test_cli_errors_explain_a_known_code() -> None:
    """Explaining a code needs no credentials, because the mapping is configuration."""
    result = run(["errors", "explain", "AADSTS7000215"])
    assert result.exit_code == 0
    assert "client secret" in result.output.lower()
    assert "learn.microsoft.com" in result.output


def test_cli_errors_explain_a_message_carrying_a_code() -> None:
    """A whole error message can be pasted in."""
    result = run(["errors", "explain", "AADSTS50011: The redirect URI does not match."])
    assert result.exit_code == 0
    assert "redirect" in result.output.lower()


def test_cli_errors_explain_an_unknown_code_exits_non_zero() -> None:
    """An unrecognised code still yields guidance, and a non zero exit code."""
    result = run(["errors", "explain", "AADSTS999999"])
    assert result.exit_code == EXIT_CHECKS_FAILED
    assert "learn.microsoft.com" in result.output


def test_cli_errors_list_and_search() -> None:
    """Every code can be listed, and searched by fragment or meaning."""
    listed = run(["errors", "list"])
    assert "AADSTS50011" in listed.output
    found = run(["errors", "search", "secret"])
    assert "AADSTS7000215" in found.output


@responses.activate
def test_cli_output_formats(authenticated: None) -> None:
    """Each format renders the same data."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json=load_fixture("applications"),
        status=200,
    )
    result = run(
        ["--auth", "file", "--output", "json", "discover", "apps", "--no-details"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload[0]["display_name"] == "Confidential web application"
    assert payload[0]["credentials"][0]["state"] in ("valid", "expiring", "expired")


@responses.activate
def test_an_api_failure_is_a_message_not_a_stack_trace(authenticated: None) -> None:
    """A Graph refusal prints its summary and exits with the API code."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json={"error": {"code": "Authorization_RequestDenied", "message": "no"}},
        status=403,
    )
    result = run(["--auth", "file", "discover", "apps", "--no-details"])
    assert result.exit_code == EXIT_API
    assert "Authorization_RequestDenied" in result.output


def test_help_text_style() -> None:
    """Help text is Oxford English and free of dash punctuation in prose."""
    commands = [
        [],
        ["discover"],
        ["discover", "apps"],
        ["discover", "sps"],
        ["logs"],
        ["logs", "audit"],
        ["logs", "signins"],
        ["logs", "graph-activity"],
        ["errors"],
        ["errors", "explain"],
        ["doctor"],
    ]
    american = ("organize", "authorize", "recognize", "color", "analyze", "behavior")
    for command in commands:
        output = CliRunner().invoke(cli, [*command, "--help"]).output
        prose = "\n".join(
            line
            for line in output.splitlines()
            if line.startswith("  ") and not line.strip().startswith("-")
        )
        lowered = prose.lower()
        for word in american:
            assert word not in lowered, f"{command} help uses {word}"
        assert " - " not in prose, f"{command} help uses dash punctuation"
        assert "--" not in prose.replace("--help", ""), f"{command} prose has a dash"


def test_machine_readable_output_is_quiet(authenticated: None) -> None:
    """A caller piping JSON does not want progress lines mixed in."""
    from entrascope.cli import log_level

    assert log_level("json", False) == "WARNING"
    assert log_level("yaml", False) == "WARNING"
    assert log_level("table", False) is None
    assert log_level("json", True) == "DEBUG"
