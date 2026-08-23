"""Command line surface tests."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import click
import pytest
import responses
import yaml
from click.testing import CliRunner

from entrascope import __version__
from entrascope.cli import cli
from entrascope.config import Config
from entrascope.render import (
    EXIT_API,
    EXIT_CHECKS_FAILED,
    EXIT_CONFIG,
    EXIT_CREDENTIALS,
)
from tests.conftest import SENTINEL_SECRET, load_fixture


def test_cli_help() -> None:
    """The root help lists the command groups."""
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    for group in ("inspect", "logs", "errors"):
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
    result = run(["--auth", "file", "discover", "applications", "--no-details"])
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
    result = run(
        ["--auth", "file", "discover", "applications", "--no-details", "--expiring"]
    )
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
    result = run(["--auth", "file", "discover", "enterprise-apps", "--no-details"])
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
        [
            "--auth",
            "file",
            "--output",
            "json",
            "discover",
            "applications",
            "--no-details",
        ]
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
    result = run(["--auth", "file", "discover", "applications", "--no-details"])
    assert result.exit_code == EXIT_API
    assert "Authorization_RequestDenied" in result.output


def test_help_text_style() -> None:
    """Help text is Oxford English and free of dash punctuation in prose."""
    commands = [
        [],
        ["discover"],
        ["discover", "applications"],
        ["discover", "enterprise-apps"],
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
        # A flag or an identifier may carry a hyphen, which is syntax. What is
        # forbidden is a dash used as punctuation in a sentence.
        without_flags = re.sub(r"(?<![\w-])--?[a-z][\w-]*", "", prose)
        for dash in (" - ", " -- ", "\u2013", "\u2014"):
            assert dash not in without_flags, f"{command} help uses dash punctuation"


def test_machine_readable_output_is_quiet(authenticated: None) -> None:
    """A caller piping JSON does not want progress lines mixed in."""
    from entrascope.cli import log_level

    assert log_level("json", False) == "WARNING"
    assert log_level("yaml", False) == "WARNING"
    assert log_level("table", False) is None
    assert log_level("json", True) == "DEBUG"


@responses.activate
def test_cli_investigate_tenant_wide(authenticated: None) -> None:
    """A tenant wide investigation ranks findings worst first."""
    from tests.test_investigate import register_graph

    register_graph()
    result = run(["--auth", "file", "investigate", "--limit", "10"])
    assert result.exit_code == EXIT_CHECKS_FAILED
    assert "Findings for the whole tenant" in result.output
    assert "error" in result.output


@responses.activate
def test_cli_investigate_one_application(authenticated: None) -> None:
    """A target narrows the report to one application."""
    from tests.test_investigate import register_graph

    register_graph()
    result = run(["--auth", "file", "investigate", "Confidential web", "--limit", "10"])
    assert "Findings for Confidential web" in result.output
    assert "Single page application" not in result.output
    assert "expired" in result.output


@responses.activate
def test_cli_investigate_a_healthy_application_reports_nothing(
    authenticated: None,
) -> None:
    """An application with nothing wrong produces no findings and exits zero."""
    from tests.test_investigate import register_graph

    register_graph()
    result = run(["--auth", "file", "investigate", "Single page", "--limit", "10"])
    assert result.exit_code == 0
    assert "No findings for Single page" in result.output


@responses.activate
def test_cli_investigate_severity_filter(authenticated: None) -> None:
    """Asking for errors shows only what is already broken."""
    from tests.test_investigate import register_graph

    register_graph()
    result = run(
        ["--auth", "file", "investigate", "--severity", "error", "--limit", "10"]
    )
    assert "warning" not in result.output.split("Findings")[1]


@responses.activate
def test_cli_investigate_json_carries_everything(authenticated: None) -> None:
    """The machine readable form carries the findings and their sources."""
    from tests.test_investigate import register_graph

    register_graph()
    result = run(["--auth", "file", "--output", "json", "investigate", "--limit", "10"])
    payload = json.loads(result.stdout)[0]
    assert payload["scope"] == "tenant"
    assert payload["findings"]
    assert {"applications", "service_principals", "audit_events", "sign_ins"} <= set(
        payload
    )


@responses.activate
def test_cli_investigate_clean_target_exits_zero(authenticated: None) -> None:
    """Nothing wrong means nothing to report, and a zero exit code."""
    from tests.test_investigate import register_graph

    register_graph()
    result = run(["--auth", "file", "investigate", "no-such-application"])
    assert result.exit_code == 0
    assert "No findings" in result.output


@responses.activate
def test_cli_logs_audit_failures_only(authenticated: None) -> None:
    """Failed directory operations can be isolated."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/directoryAudits",
        json=load_fixture("audit_events"),
        status=200,
    )
    result = run(["--auth", "file", "logs", "audit", "--failures-only"])
    assert "Add app role assignment" in result.output
    assert "Update application" not in result.output


def test_a_bare_invocation_shows_the_help() -> None:
    """Somebody typing the name alone must be told what they can do."""
    result = run([])
    assert "Commands:" in result.output
    assert "investigate" in result.output
    assert "Where to start:" in result.output


def test_every_group_shows_its_commands_when_given_none() -> None:
    """A group with no subcommand lists them rather than doing nothing."""
    for group, expected in (
        ("discover", "applications"),
        ("logs", "signins"),
        ("errors", "explain"),
        ("serve", "stdio"),
    ):
        result = run([group])
        assert "Commands:" in result.output, group
        assert expected in result.output, group


def test_a_required_argument_shows_the_help_rather_than_an_error() -> None:
    """Somebody who forgot the argument is told what it is."""
    result = run(["errors", "explain"])
    assert "Usage:" in result.output
    assert "CODE" in result.output


def test_the_root_help_defines_the_terminology() -> None:
    """One thing has one name, and the help says which."""
    output = run(["--help"]).output
    for term in ("application registration", "enterprise application"):
        assert term in output


def test_the_examples_are_not_rewrapped() -> None:
    """An example an engineer can copy has to survive the formatter."""
    output = run(["logs", "--help"]).output
    assert "entrascope logs signins --kind service-principal --failures-only" in output


def test_the_application_selector_is_described_the_same_way_everywhere() -> None:
    """One idea, one description, so the option means the same thing each time."""
    for command in (
        ["discover", "applications"],
        ["discover", "enterprise-apps"],
        ["logs", "audit"],
        ["logs", "signins"],
        ["logs", "graph-activity"],
    ):
        output = " ".join(run([*command, "--help"]).output.split())
        assert "--app" in output, command
        assert "part of a display name" in output, command


def test_the_short_aliases_still_resolve() -> None:
    """Nobody has to relearn a name they were already typing."""
    for alias, full in (("apps", "applications"), ("sps", "enterprise-apps")):
        result = run(["discover", alias, "--help"])
        assert result.exit_code == 0
        assert f"discover {full}" in result.output
    listing = run(["discover", "--help"]).output
    assert " apps " not in listing
    assert " sps " not in listing


def test_a_misplaced_subcommand_says_where_it_lives() -> None:
    """Somebody with the right idea and the wrong path is told the path."""
    result = run(["audit"])
    assert result.exit_code != 0
    assert "entrascope logs audit" in result.output


def test_a_misplaced_subcommand_also_shows_its_help() -> None:
    """Being corrected and then having to type again to see the options is rude."""
    output = run(["audit"]).output
    assert "Usage: entrascope logs audit" in output
    assert "--failures-only" in output
    assert "Usage: entrascope entrascope" not in output


def test_an_unknown_command_is_still_an_unknown_command() -> None:
    """A name that is nowhere gets the ordinary message."""
    result = run(["nonsense"])
    assert result.exit_code != 0
    assert "No such command" in result.output


def test_global_options_work_after_the_subcommand() -> None:
    """Nobody should have to remember which side of the subcommand they go on."""
    for arguments in (
        ["--output", "json", "errors", "explain", "AADSTS50011"],
        ["errors", "explain", "AADSTS50011", "--output", "json"],
    ):
        result = run(arguments)
        assert result.exit_code == 0, arguments
        assert json.loads(result.stdout)[0]["code"] == "AADSTS50011"


def test_the_timezone_option_is_available_on_either_side() -> None:
    """Timestamps are shown where the reader wants them."""
    for command in (["logs", "audit"], ["investigate"], ["doctor"]):
        output = " ".join(run([*command, "--help"]).output.split())
        assert "--timezone" in output


def test_the_plain_format_is_offered_everywhere() -> None:
    """The copy and paste format is not a hidden feature."""
    output = " ".join(run(["--help"]).output.split())
    assert "table|plain|json|yaml" in output


@responses.activate
def test_the_audit_listing_names_the_kind_of_object(authenticated: None) -> None:
    """A target that only says a name leaves the reader guessing which object."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/directoryAudits",
        json=load_fixture("audit_events"),
        status=200,
    )
    result = run(["--auth", "file", "--output", "plain", "logs", "audit"])
    header, first = result.stdout.splitlines()[:2]
    assert "target_type" in header
    assert "target_id" in header
    assert "application registration" in first


@responses.activate
def test_a_listing_says_how_long_it_was(authenticated: None) -> None:
    """A screen of rows should say how many there were."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/directoryAudits",
        json=load_fixture("audit_events"),
        status=200,
    )
    result = run(["--auth", "file", "logs", "audit"])
    assert "2 audit events" in result.output


def test_the_default_listing_is_small() -> None:
    """A log listing is for reading, and a wall of rows is not."""
    from entrascope.config import load_config

    assert load_config().tables.defaults.row_limit <= 25


def test_logs_kinds_describes_each_kind() -> None:
    """The graph filter is ours to worry about. What it covers is theirs."""
    output = run(["logs", "kinds"]).output
    assert "Interactive user sign ins" in output
    assert "signInEventTypes" not in output


def test_logs_kinds_can_name_one() -> None:
    """Naming a kind shows that one, and an unknown one says which exist."""
    assert "managed-identity" not in run(["logs", "kinds", "interactive"]).output
    unknown = run(["logs", "kinds", "telepathy"])
    assert unknown.exit_code == EXIT_CONFIG
    assert "service-principal" in unknown.output


def test_an_interrupt_leaves_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raising SystemExit would join every worker and print a second traceback.

    An engineer who pressed control C wants the process gone, with whatever it
    had already written kept.
    """
    from entrascope import cli as cli_module

    left: dict[str, int] = {}
    monkeypatch.setattr(
        cli_module.os, "_exit", lambda code: left.setdefault("code", code)
    )

    @cli_module.handled
    def interrupted() -> None:
        raise KeyboardInterrupt

    interrupted()
    assert left["code"] == 130


@responses.activate
def test_cli_inspect(authenticated: None) -> None:
    """Inspecting one application prints the whole report as YAML."""
    from tests.test_inspect import register as register_inspect

    register_inspect()
    result = run(["--auth", "file", "inspect", "Confidential web"])
    assert result.exit_code == 0, result.output
    parsed = yaml.safe_load(result.stdout)
    assert parsed["identity"]["display_name"] == "Confidential web application"
    assert "consent" in parsed["permissions"]


@responses.activate
def test_cli_inspect_as_json(authenticated: None) -> None:
    """The same report, for a machine."""
    from tests.test_inspect import register as register_inspect

    register_inspect()
    result = run(["--auth", "file", "--output", "json", "inspect", "Confidential web"])
    assert json.loads(result.stdout)["identity"]["application_type"] == (
        "confidential-client"
    )


@responses.activate
def test_cli_inspect_without_a_target_and_without_a_terminal(
    authenticated: None,
) -> None:
    """With nothing to draw the list on, the help is the whole answer.

    Reading the entire directory to then find nobody to offer it to would be a
    slow way of saying nothing.
    """
    from tests.test_inspect import register as register_inspect

    register_inspect()
    result = run(["--auth", "file", "inspect"])
    assert result.exit_code == 0
    assert "part of a display name" in result.output
    assert "Commands:" in result.output


@responses.activate
def test_cli_whoami(authenticated: None) -> None:
    """The identity report names the tenant and what the token carries."""
    responses.add(
        responses.GET,
        f"{ROOT}/organization",
        json={"value": [{"id": "tenant-1", "displayName": "A Tenant"}]},
        status=200,
    )
    responses.add(
        responses.GET,
        re.compile(rf"{re.escape(ROOT)}/servicePrincipals\(appId="),
        json={"value": []},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{ROOT}/identity/conditionalAccess/policies",
        json={"value": []},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://management.azure.com/tenants",
        json={"value": []},
        status=200,
    )
    result = run(["--auth", "file", "whoami"])
    assert result.exit_code == 0, result.output
    parsed = yaml.safe_load(result.stdout)
    assert parsed["tenant"]["display_name"] == "A Tenant"
    assert parsed["authentication"]["source"] == "file"


@responses.activate
def test_cli_gallery(authenticated: None) -> None:
    """The gallery answers whether an application is available ready made."""
    responses.add(
        responses.GET,
        f"{ROOT}/applicationTemplates",
        json={
            "value": [
                {
                    "displayName": "Amazon Web Services",
                    "publisher": "Amazon",
                    "supportedSingleSignOnModes": ["saml"],
                }
            ]
        },
        status=200,
    )
    result = run(["--auth", "file", "discover", "gallery", "amazon"])
    assert "Amazon Web Services" in result.output
    assert "saml" in result.output


def test_the_monitor_route_explains_itself_without_a_workspace() -> None:
    """Being told to pass a flag is no use to somebody who has no workspace."""
    result = run(["logs", "graph-activity"])
    assert result.exit_code == EXIT_CONFIG
    assert "only through Azure Monitor" in result.output
    assert "logs audit" in result.output
    assert "diagnostic setting" in result.output


def test_the_monitor_route_uses_a_configured_workspace() -> None:
    """Setting it once should stop the asking."""
    from entrascope.cli import require_workspace
    from entrascope.config import load_config

    config = load_config()
    with_workspace = config.model_copy(
        update={"tables": config.tables.model_copy(update={"workspace_id": "w-1"})}
    )
    assert require_workspace(None, with_workspace) == "w-1"
    assert require_workspace("explicit", with_workspace) == "explicit"


def test_the_servers_explain_a_missing_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A half installed dependency should be a sentence, not a stack trace."""
    from entrascope import cli as cli_module

    monkeypatch.setattr(cli_module, "find_spec", lambda name: None)
    monkeypatch.setattr(
        cli_module,
        "import_module",
        lambda name: (_ for _ in ()).throw(ImportError("no fastmcp")),
    )
    result = run(["serve", "stdio"])
    assert result.exit_code == EXIT_CONFIG
    assert "fastmcp is not installed" in result.output
    assert "force-reinstall" in result.output


def test_the_servers_explain_a_broken_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installed but unimportable is a different problem with a different fix."""
    from entrascope import cli as cli_module

    monkeypatch.setattr(cli_module, "find_spec", lambda name: object())
    monkeypatch.setattr(
        cli_module,
        "import_module",
        lambda name: (_ for _ in ()).throw(ImportError("cannot import name FastMCP")),
    )
    result = run(["serve", "http"])
    assert result.exit_code == EXIT_CONFIG
    assert "force-reinstall" in result.output


def test_config_path_says_where_it_reads_from() -> None:
    """An installed tool reads from inside the package, which surprises people."""
    result = run(["config", "path"])
    assert result.exit_code == 0
    assert "_config" in result.output
    assert "in use" in result.output


def test_config_export_takes_a_copy(tmp_path: Path) -> None:
    """The packaged copy is replaced on upgrade, so an edit needs a copy."""
    target = tmp_path / "mine"
    result = run(["config", "export", str(target)])
    assert result.exit_code == 0
    assert (target / "endpoints.yaml").is_file()
    assert (target / "kql" / "graph_activity.kql").is_file()
    assert "ENTRASCOPE_CONFIG_DIR" in result.output


def test_config_export_refuses_to_clobber(tmp_path: Path) -> None:
    """Overwriting somebody's edited configuration must be asked for."""
    target = tmp_path / "mine"
    run(["config", "export", str(target)])
    again = run(["config", "export", str(target)])
    assert again.exit_code == EXIT_CONFIG
    assert "--force" in again.output
    assert run(["config", "export", str(target), "--force"]).exit_code == 0


def test_config_show_prints_one_file() -> None:
    """Reading the file in force, whichever directory that is."""
    result = run(["config", "show", "tables.yaml"])
    assert result.exit_code == 0
    assert "diagnostic_categories" in result.output


def test_config_show_refuses_a_path_outside_the_directory() -> None:
    """A name is a name, not a path to anywhere on the machine."""
    for name in ("../../etc/passwd", "/etc/passwd"):
        result = run(["config", "show", name])
        assert result.exit_code == EXIT_CONFIG
        assert "No configuration file named" in result.output


def test_upgrade_check_reports_without_changing_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asking is not doing."""
    from entrascope import cli as cli_module

    monkeypatch.setattr(cli_module, "newer_release", lambda config, force=False: None)
    result = run(["upgrade", "--check"])
    assert result.exit_code == 0
    assert "running version" in result.output
    assert "upgrade command" in result.output


def test_upgrade_says_when_there_is_nothing_to_do(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The commonest case should be one line."""
    from entrascope import cli as cli_module

    monkeypatch.setattr(cli_module, "newer_release", lambda config, force=False: None)
    result = run(["upgrade"])
    assert "is the newest version" in result.output


def test_upgrade_runs_the_command_and_says_what_it_ran(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An upgrade nobody can see is an upgrade nobody can debug."""
    from entrascope import cli as cli_module
    from entrascope.upgrade import Release

    monkeypatch.setattr(
        cli_module,
        "latest_release",
        lambda config, force=False: Release(version="v9.9.9", url="https://n.invalid"),
    )
    monkeypatch.setattr(
        cli_module,
        "run_upgrade",
        lambda config, break_system_packages=False: (["pip", "install"], "done"),
    )
    result = run(["upgrade"])
    assert "Upgrading from" in result.output
    assert "Ran: pip install" in result.output
    assert "https://n.invalid" in result.output


def test_the_version_notice_stays_out_of_machine_output(config: Config) -> None:
    """A warning inside a JSON payload breaks whatever was parsing it."""
    from entrascope.cli import announce_new_version

    for output in ("json", "yaml", "plain"):
        announce_new_version(config, output)  # must not raise and must not fetch


def test_the_version_notice_is_skipped_without_a_terminal(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nobody is reading it, and it would land in whatever captured the output."""
    from entrascope import cli as cli_module

    called: list[int] = []
    monkeypatch.setattr(
        cli_module, "newer_release", lambda cfg: called.append(1) or None
    )
    cli_module.announce_new_version(config, "table")
    assert not called


def test_upgrade_is_not_offered_as_a_tool() -> None:
    """Installing software is a decision for the person at the keyboard."""
    from entrascope.mcp_tools import NOT_EXPOSED

    assert "upgrade" in NOT_EXPOSED
    assert "person at the keyboard" in NOT_EXPOSED["upgrade"]


def test_a_group_with_no_subcommand_still_prints_its_help_when_piped() -> None:
    """A script or a pipe gets exactly what it always got."""
    for group in ("errors", "logs", "inspect", "config", "serve"):
        output = run([group]).output
        assert "Commands:" in output, group
        assert "Usage:" in output, group


def test_the_command_chooser_is_skipped_without_a_terminal() -> None:
    """There is nothing to draw on, so the help is the whole answer."""
    result = run(["errors"])
    assert result.exit_code == 0
    assert "Commands:" in result.output


def test_a_chosen_command_is_asked_for_the_argument_it_needs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Running it and then complaining that an argument is missing is rude.

    The chooser asks for whatever the command cannot do without, then runs it.
    """
    from entrascope import cli as cli_module
    from entrascope.cli import SETTINGS, build_settings

    asked: list[str] = []
    monkeypatch.setattr(
        cli_module.click,
        "prompt",
        lambda label, **kwargs: asked.append(label) or "AADSTS50011",
    )
    errors_group = cli.commands["errors"]
    assert isinstance(errors_group, click.Group)
    explain_command = errors_group.commands["explain"]

    parent = click.Context(
        cli, obj={SETTINGS: build_settings(None, None, "json", False)}
    )
    with parent:
        cli_module.run_command(explain_command, "explain", parent)
    assert asked == ["Code (blank to go back)"]


def test_a_command_needing_nothing_is_run_straight_away() -> None:
    """Only a required argument is worth interrupting somebody for."""
    from entrascope import cli as cli_module
    from entrascope.cli import SETTINGS, build_settings

    errors_group = cli.commands["errors"]
    assert isinstance(errors_group, click.Group)
    parent = click.Context(
        cli, obj={SETTINGS: build_settings(None, None, "json", False)}
    )
    with parent:
        cli_module.run_command(errors_group.commands["list"], "list", parent)


def test_the_chooser_labels_every_command_with_its_purpose() -> None:
    """A list of bare names is a list nobody can choose from."""
    from entrascope.cli import summary

    errors_group = cli.commands["errors"]
    assert isinstance(errors_group, click.Group)
    for command in errors_group.commands.values():
        assert summary(command)


def test_a_broken_version_check_never_stops_a_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The command an engineer ran matters. Knowing about a release does not."""
    from entrascope import cli as cli_module

    def explode(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("the check itself is broken")

    monkeypatch.setattr(cli_module, "newer_release", explode)
    result = run(["errors", "explain", "AADSTS50011"])
    assert result.exit_code == 0
    assert "redirect" in result.output.lower()


def test_a_broken_version_check_does_not_stop_the_upgrade_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Least of all the command whose whole job is to fix it."""

    def explode(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("the feed itself is broken")

    monkeypatch.setattr("entrascope.upgrade.fetch_release", explode)
    monkeypatch.setattr("entrascope.upgrade.read_cache", explode)
    result = run(["upgrade", "--check"])
    assert result.exit_code == 0
    assert "running version" in result.output


@responses.activate
def test_a_failure_says_which_identity_it_used(authenticated: None) -> None:
    """The first question after a refusal is always which identity was refused."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json={"error": {"code": "Authorization_RequestDenied", "message": "no"}},
        status=403,
    )
    result = run(["--auth", "file", "discover", "applications", "--no-details"])
    assert result.exit_code == EXIT_API
    assert "Authenticated as: client credentials from" in result.output


def test_an_unsafe_credential_file_stops_the_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rather than being worked around, which is what used to happen."""
    from entrascope.config import load_config
    from tests.test_credentials import write_credentials

    write_credentials(tmp_path, config=load_config(), directory_mode=0o750)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    monkeypatch.setattr("entrascope.credentials.shutil.which", lambda _: "/usr/bin/az")
    result = run(["logs", "audit"])
    assert result.exit_code == EXIT_CREDENTIALS
    assert "will not work around it" in result.output
    assert "chmod 0700" in result.output


@responses.activate
def test_a_missing_permission_prints_the_command_that_grants_it(
    authenticated: None,
) -> None:
    """Microsoft names the permission it wanted, and entrascope knows its
    identifier and the application it authenticated as. Printing the exact
    command beats telling somebody to look one up."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/directoryAudits",
        json={
            "error": {
                "code": "Authentication_MSGraphPermissionMissing",
                "message": (
                    "The principal does not have required Microsoft Graph "
                    "permission(s): AuditLog.Read.All to call this API."
                ),
            }
        },
        status=403,
    )
    result = run(["--auth", "file", "logs", "audit"])
    assert result.exit_code == EXIT_API
    assert "Grant it with:" in result.output
    assert "az ad app permission add --id 11111111" in result.output
    assert "b0afded3-3588-46d8-8b3d-9842eff778da=Role" in result.output
    assert "admin-consent" in result.output


@responses.activate
def test_a_refusal_naming_no_permission_prints_no_command(
    authenticated: None,
) -> None:
    """A command that grants the wrong thing is worse than no command."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/directoryAudits",
        json={"error": {"code": "Authorization_RequestDenied", "message": "no"}},
        status=403,
    )
    result = run(["--auth", "file", "logs", "audit"])
    assert "Grant it with:" not in result.output


def test_a_blank_answer_goes_back_rather_than_running_the_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A prompt whose only exit is the interrupt key is a trap."""
    from entrascope import cli as cli_module
    from entrascope.cli import SETTINGS, build_settings

    monkeypatch.setattr(cli_module.click, "prompt", lambda label, **kwargs: "")
    errors_group = cli.commands["errors"]
    assert isinstance(errors_group, click.Group)
    parent = click.Context(
        cli, obj={SETTINGS: build_settings(None, None, "json", False)}
    )
    with parent:
        assert (
            cli_module.run_command(errors_group.commands["explain"], "explain", parent)
            is None
        )


def test_the_menu_returns_after_each_command_until_it_is_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finishing a command should not put somebody back at the shell."""
    from entrascope import cli as cli_module
    from entrascope.cli import LEAVE, SETTINGS, build_settings

    picked = iter(["list", "list", LEAVE])
    monkeypatch.setattr(cli_module, "available", lambda: True)
    monkeypatch.setattr(cli_module, "choose", lambda *a, **k: next(picked))
    ran: list[str] = []
    monkeypatch.setattr(
        cli_module, "run_command", lambda command, name, ctx: ran.append(name)
    )
    errors_group = cli.commands["errors"]
    assert isinstance(errors_group, click.Group)
    parent = click.Context(
        cli, obj={SETTINGS: build_settings(None, None, "json", False)}
    )
    with parent:
        cli_module.offer_commands(errors_group, parent)
    assert ran == ["list", "list"]


def test_the_menu_offers_a_way_out_of_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guessing that escape leaves is not something anybody should have to do."""
    from entrascope import cli as cli_module
    from entrascope.cli import LEAVE, SETTINGS, build_settings

    offered: list[list[Any]] = []

    def record(lines: Any, **kwargs: Any) -> str:
        offered.append(list(lines))
        return LEAVE

    monkeypatch.setattr(cli_module, "available", lambda: True)
    monkeypatch.setattr(cli_module, "choose", record)
    errors_group = cli.commands["errors"]
    assert isinstance(errors_group, click.Group)
    parent = click.Context(
        cli, obj={SETTINGS: build_settings(None, None, "json", False)}
    )
    with parent:
        cli_module.offer_commands(errors_group, parent)
    assert [line.key for line in offered[0]][-1] == LEAVE


def test_a_command_that_fails_returns_to_the_menu(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Losing the session over a mistyped identifier would be miserable."""
    from entrascope import cli as cli_module
    from entrascope.cli import SETTINGS, build_settings
    from entrascope.models import ConfigError

    def explode(command: Any, name: str, ctx: Any) -> None:
        raise ConfigError("nothing by that name")

    monkeypatch.setattr(cli_module, "run_command", explode)
    errors_group = cli.commands["errors"]
    assert isinstance(errors_group, click.Group)
    parent = click.Context(
        cli, obj={SETTINGS: build_settings(None, None, "json", False)}
    )
    with parent:
        assert cli_module.attempt(errors_group.commands["list"], "list", parent) is None


def test_config_show_names_the_files_it_read() -> None:
    """Knowing the setting without knowing which file holds it is half an answer."""
    result = run(["config", "show"])
    assert result.exit_code == 0
    assert "sources:" in result.output
    assert "in_use:" in result.output
    assert "settings:" in result.output
    assert "fields.yaml" in result.output


def test_config_show_still_prints_one_file_with_its_path() -> None:
    """Naming a file is still the way to read only that file."""
    result = run(["config", "show", "fields.yaml"])
    assert result.exit_code == 0
    assert "fields.yaml" in result.output.splitlines()[0]


def test_after_reading_an_application_the_choice_is_a_menu(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A question with only yes and no for answers cannot offer a file."""
    from entrascope import cli as cli_module
    from entrascope.config import load_config

    config = load_config(None)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_module, "choose", lambda *a, **k: "save")
    report = {"identity": {"display_name": "Payments API"}, "scopes": []}
    assert cli_module.after_viewing(report, config) == "list"
    assert (tmp_path / "Payments-API.yaml").is_file()


def test_leaving_after_reading_an_application_is_an_option(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Going back to the list is the usual answer, not the only one."""
    from entrascope import cli as cli_module
    from entrascope.config import load_config

    monkeypatch.setattr(cli_module, "choose", lambda *a, **k: "quit")
    assert cli_module.after_viewing({}, load_config(None)) == "quit"


def test_escape_from_the_menu_goes_back_to_the_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Escape means go back, and going back to the list is one step back."""
    from entrascope import cli as cli_module
    from entrascope.config import load_config

    monkeypatch.setattr(cli_module, "choose", lambda *a, **k: None)
    assert cli_module.after_viewing({}, load_config(None)) == "list"


def test_a_saved_application_is_named_after_itself(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A name with a slash in it is still a name, and must not be a path."""
    from entrascope import cli as cli_module
    from entrascope.config import load_config

    monkeypatch.chdir(tmp_path)
    cli_module.save_report(
        {"identity": {"display_name": "Team A/B testing"}}, load_config(None)
    )
    assert (tmp_path / "Team-A-B-testing.yaml").is_file()


def test_listing_and_reading_are_one_command() -> None:
    """Two commands asking the same question at two depths is one command."""
    inspect_group = cli.commands["inspect"]
    assert isinstance(inspect_group, click.Group)
    assert set(inspect_group.commands) >= {
        "app",
        "applications",
        "enterprise-apps",
        "gallery",
    }


def test_the_old_name_still_reaches_the_command() -> None:
    """Tidying a command list is not worth breaking somebody's script over."""
    context = click.Context(cli)
    assert cli.get_command(context, "discover") is cli.commands["inspect"]


def test_a_name_that_is_not_a_subcommand_is_an_application() -> None:
    """entrascope inspect saml2 has always meant one application."""
    inspect_group = cli.commands["inspect"]
    assert isinstance(inspect_group, click.Group)
    context = click.Context(inspect_group)
    name, command, _ = inspect_group.resolve_command(context, ["saml2"])
    assert name == "app"
    assert command is inspect_group.commands["app"]


def test_a_refusal_is_printed_rather_than_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refusal shown as a stack trace reads as a crash, not as an answer."""
    from entrascope import cli as cli_module
    from entrascope.models import EntrascopeError

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise EntrascopeError("This Python is managed by something other than pip.")

    from entrascope.upgrade import Release

    monkeypatch.setattr(cli_module, "run_upgrade", refuse)
    monkeypatch.setattr(
        cli_module,
        "latest_release",
        lambda *a, **k: Release(version="v9.9.9", url="https://example.invalid"),
    )
    result = run(["upgrade"])
    assert result.exit_code != 0
    assert "managed by something other than pip" in result.output
    assert "Traceback" not in result.output


@responses.activate
def test_investigate_can_follow_instead_of_reporting_once(
    authenticated: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A report that prints once cannot answer what is happening now."""
    from entrascope import cli as cli_module
    from tests.test_investigate import register_graph

    register_graph()
    watched: list[str] = []
    monkeypatch.setattr(
        cli_module,
        "follow_tenant",
        lambda config, token, **kwargs: watched.append(kwargs.get("app_id", "")),
    )
    result = run(["--auth", "file", "investigate", "--follow"])
    assert result.exit_code == 0
    assert watched == [""]


def test_the_menu_after_an_investigation_offers_the_live_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reading the findings and being dropped at the shell is rarely the end."""
    from entrascope import cli as cli_module
    from entrascope.config import load_config

    monkeypatch.setattr(cli_module, "choose", lambda *a, **k: "watch")
    assert cli_module.after_findings(investigation(), load_config(None)) == "watch"


def test_findings_can_be_saved_from_the_menu(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Six hundred findings are worth keeping rather than scrolling past."""
    from entrascope import cli as cli_module
    from entrascope.config import load_config

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_module, "choose", lambda *a, **k: "save")
    assert cli_module.after_findings(investigation(), load_config(None)) == "save"
    assert (tmp_path / "investigation-the-whole-tenant.yaml").is_file()


def investigation() -> Any:
    """Return one investigation of a whole tenant, with nothing in it."""
    from entrascope.models import Investigation

    return Investigation(
        target="the whole tenant",
        scope="tenant",
        applications=(),
        service_principals=(),
        audit_events=(),
        sign_ins=(),
        findings=(),
    )


def test_a_finding_names_the_application_it_is_about() -> None:
    """An error message quotes the identifier and never the display name."""
    from entrascope.cli import FINDING_TABLE_COLUMNS

    assert "identifier" in FINDING_TABLE_COLUMNS
    assert "when" in FINDING_TABLE_COLUMNS
    assert "occurrences" not in FINDING_TABLE_COLUMNS


def test_the_menu_waits_before_drawing_over_what_a_command_said(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The menu is drawn over the screen, so it must not repaint at once."""
    from entrascope import cli as cli_module
    from entrascope.cli import LEAVE, SETTINGS, build_settings

    picked = iter(["list", LEAVE])
    waited: list[str] = []
    monkeypatch.setattr(cli_module, "available", lambda: True)
    monkeypatch.setattr(cli_module, "choose", lambda *a, **k: next(picked))
    monkeypatch.setattr(cli_module, "run_command", lambda *a: None)
    monkeypatch.setattr(cli_module.click, "pause", lambda text: waited.append(text))
    errors_group = cli.commands["errors"]
    assert isinstance(errors_group, click.Group)
    parent = click.Context(
        cli, obj={SETTINGS: build_settings(None, None, "json", False)}
    )
    with parent:
        cli_module.offer_commands(errors_group, parent)
    assert waited and "menu" in waited[0]


def test_a_command_that_exits_with_a_code_returns_to_the_menu(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A finding is not a reason to end somebody's session."""
    from entrascope import cli as cli_module
    from entrascope.cli import SETTINGS, build_settings

    def fail(command: Any, name: str, ctx: Any) -> None:
        raise SystemExit(1)

    monkeypatch.setattr(cli_module, "run_command", fail)
    errors_group = cli.commands["errors"]
    assert isinstance(errors_group, click.Group)
    parent = click.Context(
        cli, obj={SETTINGS: build_settings(None, None, "json", False)}
    )
    with parent:
        assert cli_module.attempt(errors_group.commands["list"], "list", parent) is None


def test_config_export_goes_where_it_can_be_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A configuration directory is the wrong place for a file to be read."""
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_DOWNLOAD_DIR", raising=False)
    result = run(["config", "export"])
    assert result.exit_code == 0
    assert (downloads / "endpoints.yaml").is_file()
    assert "for reading" in result.output


def test_config_export_can_go_where_it_takes_effect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The copy that counts is the one entrascope reads."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    result = run(["config", "export", "--use"])
    assert result.exit_code == 0
    assert (tmp_path / "config" / "entrascope" / "endpoints.yaml").is_file()
    assert "used automatically" in result.output


def test_upgrade_says_where_the_files_are(monkeypatch: pytest.MonkeyPatch) -> None:
    """Somebody who cannot run the installer can still fetch the wheel."""
    from entrascope import cli as cli_module
    from entrascope.upgrade import Release

    wheel = "https://example.invalid/entrascope-9.9.9-py3-none-any.whl"
    monkeypatch.setattr(
        cli_module,
        "latest_release",
        lambda *a, **k: Release(
            version="v9.9.9", url="https://example.invalid", files=(wheel,)
        ),
    )
    monkeypatch.setattr(cli_module, "run_upgrade", lambda *a, **k: (["pip"], "done"))
    result = run(["upgrade"])
    assert wheel in result.output


def test_upgrade_check_names_the_files_even_when_up_to_date(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asking what is published is worth answering however old this copy is."""
    from entrascope import cli as cli_module
    from entrascope.upgrade import Release

    monkeypatch.setattr(
        cli_module,
        "latest_release",
        lambda *a, **k: Release(
            version="v0.0.1", url="https://example.invalid", files=("wheel.whl",)
        ),
    )
    result = run(["upgrade", "--check"])
    assert "wheel.whl" in result.output


def test_a_saved_file_never_writes_over_one_that_is_there(tmp_path: Path) -> None:
    """Saving is meant to keep something, not to replace what was kept."""
    from entrascope.cli import free_name

    first = tmp_path / "thing.yaml"
    first.write_text("one", encoding="utf-8")
    assert free_name(first).name == "thing-2.yaml"


def test_a_display_name_cannot_become_a_path(tmp_path: Path) -> None:
    """A display name is somebody else's text, and a slash is a directory."""
    from entrascope.cli import safe_name

    assert safe_name("../../etc/passwd", "application").name == "etc-passwd.yaml"
    assert safe_name("   ", "application").name == "application.yaml"


def test_an_export_that_would_half_finish_does_not_start(tmp_path: Path) -> None:
    """Some of one release and some of another is worse than neither."""
    from entrascope.cli import copy_configuration
    from entrascope.config import repository_config_dir
    from entrascope.models import ConfigError

    destination = tmp_path / "config"
    destination.mkdir()
    (destination / "tables.yaml").write_text("mine", encoding="utf-8")
    with pytest.raises(ConfigError):
        copy_configuration(repository_config_dir(), destination, force=False)
    assert sorted(item.name for item in destination.iterdir()) == ["tables.yaml"]


@responses.activate
def test_follow_with_machine_output_says_it_cannot(authenticated: None) -> None:
    """A flag that is ignored in silence is a flag nobody trusts again."""
    from tests.test_investigate import register_graph

    register_graph()
    result = run(["--auth", "file", "--output", "json", "investigate", "--follow"])
    assert "cannot be combined" in result.output
