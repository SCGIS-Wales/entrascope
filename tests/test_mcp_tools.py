"""MCP tool surface tests, driven through the FastMCP in memory client."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

import pytest
import responses
from click.testing import CliRunner
from fastmcp import Client

from entrascope.cli import cli
from entrascope.config import Config, load_config
from entrascope.mcp_stdio import build_server
from entrascope.mcp_tools import INSTRUCTIONS, SERVER_NAME, tool_names
from tests.conftest import SENTINEL_SECRET, load_fixture
from tests.test_credentials import write_credentials

ROOT = "https://graph.microsoft.com/v1.0"


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Build a server whose identity yields a fixed token."""
    config = load_config()
    write_credentials(tmp_path, config=config)
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
    return build_server(config, "file")


async def call(server: Any, name: str, arguments: dict[str, Any] | None = None) -> Any:
    """Call one tool through the in memory client and return its content."""
    async with Client(server) as client:
        result = await client.call_tool(name, arguments or {})
    return result.data


async def test_mcp_tool_list(server: Any) -> None:
    """Every tool is registered and described."""
    async with Client(server) as client:
        tools = await client.list_tools()
    names = {tool.name for tool in tools}
    assert names == set(tool_names())
    assert all(tool.description for tool in tools)


async def test_the_server_describes_itself(server: Any) -> None:
    """A client learns what the server is for, and where to start."""
    async with Client(server) as client:
        result = client.initialize_result
    assert result.serverInfo.name == SERVER_NAME
    assert "doctor" in INSTRUCTIONS


async def test_the_instructions_carry_the_activity_log_caveat() -> None:
    """The one thing everybody gets wrong is stated up front."""
    normalised = " ".join(INSTRUCTIONS.split())
    assert "do not appear in the Azure subscription activity" in normalised


async def test_mcp_explain_error_tool(server: Any) -> None:
    """Explaining a code needs no credentials and returns structured content."""
    data = await call(server, "explain_error", {"code": "AADSTS7000215"})
    assert data["known"] is True
    assert "secret" in data["meaning"].lower()
    assert data["docs_url"].startswith("https://learn.microsoft.com/")


async def test_mcp_list_error_codes_tool(server: Any) -> None:
    """Every code can be listed, and searched."""
    everything = await call(server, "list_error_codes")
    assert any(row["code"] == "AADSTS50011" for row in everything)
    found = await call(server, "list_error_codes", {"term": "secret"})
    assert len(found) < len(everything)


async def test_mcp_sign_in_kinds_tool(server: Any) -> None:
    """The kinds the sign_ins tool accepts are discoverable."""
    assert "service-principal" in await call(server, "sign_in_kinds")


@responses.activate
async def test_mcp_discover_tool(server: Any) -> None:
    """Discovery returns the projected applications as structured content."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json=load_fixture("applications"),
        status=200,
    )
    rows = await call(server, "discover_applications", {"with_details": False})
    assert len(rows) == 5
    assert rows[0]["display_name"] == "Confidential web application"
    assert rows[0]["credentials"][0]["state"] in ("valid", "expiring", "expired")


@responses.activate
async def test_mcp_discover_tool_filters(server: Any) -> None:
    """The filters behave the same way they do on the command line."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json=load_fixture("applications"),
        status=200,
    )
    rows = await call(
        server,
        "discover_applications",
        {"with_details": False, "application_type": "single-page-application"},
    )
    assert [row["display_name"] for row in rows] == ["Single page application"]


@responses.activate
async def test_mcp_service_principals_tool(server: Any) -> None:
    """Enterprise applications are returned with their classification."""
    responses.add(
        responses.GET,
        f"{ROOT}/servicePrincipals",
        json=load_fixture("service_principals"),
        status=200,
    )
    rows = await call(server, "discover_service_principals", {"with_details": False})
    assert {row["application_type"] for row in rows} >= {"managed-identity"}


@responses.activate
async def test_mcp_logs_tool(server: Any) -> None:
    """Audit events and sign ins are both readable as tools."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/directoryAudits",
        json=load_fixture("audit_events"),
        status=200,
    )
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/signIns",
        json=load_fixture("sign_ins"),
        status=200,
    )
    events = await call(server, "audit_events")
    assert events[0]["activity"] == "Update application"
    # The failures clause goes to Graph rather than being applied to whatever
    # the newest rows happened to be, so the request is what carries it.
    await call(server, "sign_ins", {"failures_only": True})
    asked = unquote_plus(responses.calls[-1].request.url or "")
    assert "status/errorCode ne 0" in asked


@responses.activate
async def test_mcp_audit_categories_tool(server: Any) -> None:
    """An assistant can find out which categories exist before asking for one."""
    rows = await call(server, "audit_categories")
    names = {row["category"] for row in rows}
    assert "application-management" in names
    default = next(row for row in rows if row["default"])
    assert default["category"] == "application-management"


@responses.activate
async def test_the_gallery_tool_says_when_a_match_is_only_near(server: Any) -> None:
    """The endpoint filters on a prefix, so it often answers with the nearest.

    The command says so. The tool used to return the rows alone, which left an
    assistant presenting near matches as though they were the answer.
    """
    responses.add(
        responses.GET,
        f"{ROOT}/applicationTemplates",
        json={"value": [{"displayName": "Amazon SageMaker", "publisher": "Amazon"}]},
        status=200,
    )
    result = await call(server, "gallery_applications", {"term": "amazon web"})
    assert result["applications"][0]["display_name"] == "Amazon SageMaker"
    assert result["exact"] is False
    assert "Nothing matched" in result["note"]


@responses.activate
async def test_the_enterprise_tool_excludes_microsoft_by_default(
    server: Any,
) -> None:
    """The command excludes them and the tool returned every one of them.

    A tenant carries hundreds of Microsoft first party service principals. They
    are Microsoft's to manage, and an assistant handed all of them is an
    assistant reading several hundred objects to find none of the answer.
    """
    responses.add(
        responses.GET,
        f"{ROOT}/servicePrincipals",
        json={
            "value": [
                {
                    "id": "sp-1",
                    "appId": "app-1",
                    "displayName": "Ours",
                    "servicePrincipalType": "Application",
                },
                {
                    "id": "sp-2",
                    "appId": "app-2",
                    "displayName": "Microsoft Graph",
                    "servicePrincipalType": "Application",
                    "appOwnerOrganizationId": ("f8cdef31-a31e-4b4a-93e4-5f571e91255a"),
                },
            ]
        },
        status=200,
    )
    rows = await call(server, "discover_service_principals", {"with_details": False})
    assert [row["display_name"] for row in rows] == ["Ours"]
    everything = await call(
        server,
        "discover_service_principals",
        {"with_details": False, "include_first_party": True},
    )
    assert len(everything) == 2


@responses.activate
async def test_the_discovery_tools_narrow_to_one_application(server: Any) -> None:
    """The command takes a selector, so the tool must mean the same by one."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json=load_fixture("applications"),
        status=200,
    )
    rows = await call(
        server,
        "discover_applications",
        {"with_details": False, "app": "Single page"},
    )
    assert [row["display_name"] for row in rows] == ["Single page application"]


@responses.activate
async def test_mcp_investigate_tool(server: Any) -> None:
    """The investigation is the command people reach for, and nothing ran it."""
    from tests.test_investigate import register_graph

    register_graph()
    result = await call(server, "investigate", {"limit": 10})
    assert result["scope"] == "tenant"
    assert result["findings"]
    assert {"severity", "area", "subject"} <= set(result["findings"][0])


@responses.activate
async def test_mcp_investigate_tool_narrows_to_one_application(server: Any) -> None:
    """A target narrows the sweep, the same way the command does."""
    from tests.test_investigate import register_graph

    register_graph()
    result = await call(
        server, "investigate", {"target": "Confidential web", "limit": 10}
    )
    assert result["scope"] == "application"
    assert result["target"] == "Confidential web"


@responses.activate
async def test_mcp_whoami_tool(server: Any) -> None:
    """The first question in every diagnosis, and nothing exercised it."""
    responses.add(
        responses.GET,
        f"{ROOT}/organization",
        json={"value": [{"id": "tenant-1", "displayName": "Example"}]},
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
        "https://management.azure.com/tenants",
        json={"value": []},
        status=200,
    )
    report = await call(server, "whoami", {"with_policies": False})
    assert report["authentication"]["source"] == "file"
    assert report["tenant"]["display_name"] == "Example"
    # Asking for no policies must not read them anyway.
    assert "conditional_access" not in report


@responses.activate
async def test_mcp_doctor_tool(server: Any) -> None:
    """The doctor tool returns the same checks the command renders."""
    responses.add(
        responses.GET,
        f"{ROOT}/subscribedSkus",
        json={"value": []},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings",
        json={"value": []},
        status=200,
    )
    rows = await call(server, "doctor")
    assert any(row["check"] == "network path" for row in rows)
    assert all({"check", "passed", "detail"} <= set(row) for row in rows)


async def test_mcp_tool_input_validation(server: Any) -> None:
    """A tool refuses an argument of the wrong type rather than guessing."""
    with pytest.raises(Exception, match=r"(?i)valid|type|input"):
        await call(server, "explain_error", {"code": {"not": "a string"}})


async def test_an_unknown_sign_in_kind_is_reported(server: Any) -> None:
    """A kind that does not exist names the kinds that do."""
    with pytest.raises(Exception, match="interactive"):
        await call(server, "sign_ins", {"kind": "telepathy"})


@responses.activate
async def test_mcp_no_secret_in_results(server: Any) -> None:
    """No tool result may carry the secret, whatever it touched."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json=load_fixture("applications"),
        status=200,
    )
    rows = await call(server, "discover_applications", {"with_details": False})
    assert SENTINEL_SECRET not in json.dumps(rows)


@responses.activate
async def test_mcp_result_matches_cli_json(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tool result and the command line JSON payload are the same bytes.

    This is the whole reason render.py exists. If the two ever diverge, an
    assistant and an engineer are looking at different answers to one question.
    """
    for _ in range(2):
        responses.add(
            responses.GET,
            f"{ROOT}/applications",
            json=load_fixture("applications"),
            status=200,
        )
    from_tool = await call(server, "discover_applications", {"with_details": False})
    result = CliRunner().invoke(
        cli,
        ["--auth", "file", "--output", "json", "discover", "apps", "--no-details"],
        obj={},
    )
    assert result.exit_code == 0, result.output
    assert from_tool == json.loads(result.stdout)


def test_the_tool_surface_is_read_only(config: Config) -> None:
    """No tool name suggests a write, because entrascope never writes."""
    forbidden = ("create", "update", "delete", "grant", "assign", "rotate", "set")
    for name in tool_names():
        assert not any(name.startswith(word) for word in forbidden)


def test_the_stdio_server_is_reachable_from_the_command_line() -> None:
    """The serve group documents how to run the local server."""
    result = CliRunner().invoke(cli, ["serve", "--help"], obj={})
    assert result.exit_code == 0
    assert "stdio" in result.output
    detail = CliRunner().invoke(cli, ["serve", "stdio", "--help"], obj={})
    assert "no OAuth" in detail.output


def test_stdio_keeps_standard_output_for_the_protocol() -> None:
    """Nothing but the protocol may reach standard output.

    Logging, the banner and anything else go to standard error, because a
    single stray line on standard output breaks the transport.
    """
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, "-m", "entrascope", "serve", "stdio"],
        input=b"",
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert completed.stdout == b""
    assert b"local server ready" in completed.stderr


def leaf_commands() -> list[str]:
    """Return every command path below the root, other than the servers."""
    import click

    from entrascope.cli import cli as root

    paths: list[str] = []
    context = click.Context(root)
    for name, command in sorted(root.commands.items()):
        if name == "serve":
            continue
        if isinstance(command, click.Group):
            paths.extend(
                f"{name} {child}" for child in sorted(command.commands) if child
            )
        else:
            paths.append(name)
    _ = context
    return paths


def test_the_tool_surface_covers_every_command() -> None:
    """An assistant must be able to do what an engineer can do.

    The two surfaces run the same functions, so a command with no tool is a
    gap, not a design decision.
    """
    from entrascope.mcp_tools import COMMAND_TOOLS, NOT_EXPOSED, tool_names

    missing = [
        path
        for path in leaf_commands()
        if path not in COMMAND_TOOLS and path not in NOT_EXPOSED
    ]
    assert not missing, f"commands with no tool and no stated reason: {missing}"
    assert all(reason for reason in NOT_EXPOSED.values())
    unknown = [name for name in COMMAND_TOOLS.values() if name not in tool_names()]
    assert not unknown, f"the map names tools that do not exist: {unknown}"


async def test_every_mapped_tool_is_registered(server: Any) -> None:
    """The map is checked against the running server, not only the source."""
    from entrascope.mcp_tools import COMMAND_TOOLS

    async with Client(server) as client:
        registered = {tool.name for tool in await client.list_tools()}
    assert set(COMMAND_TOOLS.values()) <= registered


async def test_the_tools_take_the_arguments_the_commands_take(server: Any) -> None:
    """A tool that cannot be told what the command can be told is not parity."""
    expected = {
        "investigate": {"target", "severity", "limit", "kinds"},
        "inspect": {"target", "application_type"},
        "discover_applications": {"app", "application_type", "expiring_only"},
        "discover_service_principals": {
            "app",
            "application_type",
            "include_first_party",
        },
        "sign_ins": {"kind", "app_id", "failures_only", "limit", "lookback_hours"},
        "audit_events": {"category", "target", "failures_only", "limit"},
        "gallery_applications": {"term", "limit"},
        "whoami": {"with_policies"},
    }
    async with Client(server) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    for name, arguments in expected.items():
        properties = set(tools[name].inputSchema.get("properties", {}))
        assert arguments <= properties, f"{name} is missing {arguments - properties}"


@responses.activate
async def test_mcp_inspect_tool(server: Any) -> None:
    """The inspect tool returns the same report the command renders."""
    from tests.test_investigate import register_graph

    register_graph()
    responses.add(
        responses.GET,
        f"{ROOT}/applications/11111111-1111-1111-1111-111111111111",
        json=load_fixture("applications")["value"][0],
        status=200,
    )
    responses.add(
        responses.GET,
        re.compile(rf"{re.escape(ROOT)}/servicePrincipals\(appId="),
        json={"value": []},
        status=200,
    )
    report = await call(server, "inspect", {"target": "Confidential web"})
    assert report["identity"]["display_name"] == "Confidential web application"
    assert "consent" in report["permissions"]
    assert report["urls"]["web_redirect_uris"]


async def test_the_configuration_can_be_read_but_not_written(server: Any) -> None:
    """An assistant should learn the vocabulary, not edit the machine."""
    from entrascope.mcp_tools import NOT_EXPOSED

    listing = await call(server, "configuration")
    assert "endpoints.yaml" in listing["files"]
    assert "signins" in listing["kql_templates"]
    one = await call(server, "configuration", {"name": "tables.yaml"})
    assert "diagnostic_categories" in one["contents"]
    assert "config export" in NOT_EXPOSED


async def test_the_configuration_tool_refuses_a_path(server: Any) -> None:
    """A name is a name, not a path to anywhere on the machine."""
    with pytest.raises(Exception, match="No configuration file"):
        await call(server, "configuration", {"name": "../../etc/passwd"})
