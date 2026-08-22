"""Command line surface tests."""

from __future__ import annotations

import json
import re
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
    """With nothing to draw on it explains how to name one instead."""
    from tests.test_inspect import register as register_inspect

    register_inspect()
    result = run(["--auth", "file", "inspect"])
    assert result.exit_code == EXIT_CONFIG
    assert "part of a display name" in result.output


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
