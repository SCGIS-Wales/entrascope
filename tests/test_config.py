"""Configuration file tests.

Phase zero validates the shape of every configuration file. The loader in
entrascope.config arrives in phase one and is tested against these same files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.conftest import CONFIG_ROOT

EXPECTED_FILES = (
    "endpoints.yaml",
    "tables.yaml",
    "error-codes.yaml",
    "capabilities.yaml",
    "retry.yaml",
    "fields.yaml",
    "logging.yaml",
    "credentials.yaml",
    "server.yaml",
)

EXPECTED_KQL = (
    "signins_failures.kql",
    "audit_applicationmanagement.kql",
    "graph_activity.kql",
)


def load(name: str) -> dict[str, Any]:
    """Parse one configuration file."""
    data = yaml.safe_load((CONFIG_ROOT / name).read_text())
    assert isinstance(data, dict)
    return data


@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_config_loads(name: str) -> None:
    """Every configuration file is present and parses."""
    assert load(name)


@pytest.mark.parametrize("name", EXPECTED_KQL)
def test_kql_templates_present(name: str) -> None:
    """Every KQL template is present and is not empty."""
    path: Path = CONFIG_ROOT / "kql" / name
    assert path.read_text().strip()


def test_endpoints_expose_graph_and_authority() -> None:
    """Endpoints carry the Graph base, the authority templates and the JWKS URI."""
    endpoints = load("endpoints.yaml")
    assert endpoints["graph"]["base_url"]
    graph_app_id = "00000003-0000-0000-c000-000000000000"
    assert endpoints["graph"]["resource_app_id"] == graph_app_id
    v2 = endpoints["authority"]["v2"]
    for key in ("issuer_template", "jwks_uri_template", "oidc_discovery_template"):
        assert "{tenant_id}" in v2[key]


def test_tables_cover_every_diagnostic_category() -> None:
    """All seven diagnostic categories the doctor checks are configured."""
    categories = {row["name"] for row in load("tables.yaml")["diagnostic_categories"]}
    assert categories == {
        "AuditLogs",
        "SignInLogs",
        "NonInteractiveUserSignInLogs",
        "ServicePrincipalSignInLogs",
        "ManagedIdentitySignInLogs",
        "ProvisioningLogs",
        "MicrosoftGraphActivityLogs",
    }


def test_capabilities_carry_the_graph_app_role_ids() -> None:
    """The four required Graph permissions are configured with their app role ids."""
    permissions = {
        row["name"]: row for row in load("capabilities.yaml")["graph_permissions"]
    }
    required = {name for name, row in permissions.items() if row["required"]}
    assert required == {
        "Application.Read.All",
        "AuditLog.Read.All",
        "Directory.Read.All",
        "Policy.Read.All",
    }
    assert permissions["Application.Read.All"]["app_role_id"] == (
        "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"
    )
    assert permissions["AppRoleAssignment.ReadWrite.All"]["required"] is False


def test_every_error_code_has_remediation_and_docs() -> None:
    """No error entry may omit its remediation or its documentation link."""
    errors = load("error-codes.yaml")
    assert errors["defaults"]["docs_url"]
    for code, entry in errors["errors"].items():
        assert entry.get("meaning"), f"{code} has no meaning"
        assert entry.get("remediation"), f"{code} has no remediation"
        assert entry.get("docs_url", "").startswith("https://learn.microsoft.com/"), (
            f"{code} has no Microsoft Learn URL"
        )


def test_every_capability_has_remediation_and_docs() -> None:
    """No capability may omit its remediation or its documentation link."""
    for capability in load("capabilities.yaml")["capabilities"]:
        assert capability["remediation"]
        assert capability["docs_url"].startswith("https://learn.microsoft.com/")


def test_redaction_configuration_present() -> None:
    """The logger configuration carries redaction keys and patterns."""
    redaction = load("logging.yaml")["redaction"]
    assert "Secret" in redaction["keys"]
    assert redaction["placeholder"]
    assert redaction["patterns"]


def test_credentials_contract_is_fixed() -> None:
    """The credential contract keys and modes are exactly as specified."""
    credentials = load("credentials.yaml")
    assert credentials["file"]["directory"] == "~/.entra"
    assert credentials["file"]["filename"] == "provisioner-credentials.json"
    assert credentials["file"]["required_file_mode"] == "0600"
    assert credentials["file"]["required_directory_mode"] == "0700"
    assert credentials["file"]["keys"] == {
        "client_id": "ClientID",
        "secret": "Secret",
        "tenant_id": "TenantID",
    }


def test_authentication_sources_are_ordered() -> None:
    """The four sources resolve in the documented order."""
    sources = load("credentials.yaml")["sources"]
    assert sources["order"] == ["file", "env", "azure-cli", "default"]
    assert sources["identity_kind"]["azure-cli"] == "delegated"


def test_config_loads_through_the_loader() -> None:
    """The loader validates every file and reports where they came from."""
    from entrascope.config import load_config

    config = load_config()
    assert config.root == CONFIG_ROOT
    assert config.endpoints.graph.paths["applications"] == "/applications"
    assert config.retry.concurrency.max_workers >= 1
    assert config.credentials.file.filename


def test_config_schema_rejects_bad_yaml(tmp_path: Path) -> None:
    """A malformed configuration directory fails at load time, and says why."""
    from entrascope.config import ConfigError, build_config, find_config_dir

    everything = (
        *EXPECTED_FILES,
        "error-codes.yaml",
        "capabilities.yaml",
        "server.yaml",
    )
    for name in everything:
        (tmp_path / name).write_text((CONFIG_ROOT / name).read_text())
    (tmp_path / "endpoints.yaml").write_text("graph: {base_url: 1}\n")
    with pytest.raises(ConfigError) as raised:
        build_config(tmp_path)
    assert "failed validation" in str(raised.value)
    assert find_config_dir(tmp_path) == tmp_path


def test_config_directory_search_reports_what_it_tried(tmp_path: Path) -> None:
    """An absent configuration directory names every path that was searched."""
    from entrascope.config import ConfigError, find_config_dir

    empty = tmp_path / "nowhere"
    empty.mkdir()
    import entrascope.config as config_module

    original = config_module.candidate_directories
    config_module.candidate_directories = lambda explicit=None: (empty,)
    try:
        with pytest.raises(ConfigError) as raised:
            find_config_dir()
    finally:
        config_module.candidate_directories = original
    assert str(empty) in str(raised.value)


def test_kql_templates_render_with_their_parameters() -> None:
    """Every template renders once its declared parameters are supplied."""
    from entrascope.config import load_config, load_kql, render_kql

    config = load_config()
    parameters = {
        "lookback_hours": 24,
        "app_filter": "",
        "target_filter": "",
        "row_limit": 50,
    }
    for name in ("signins_failures", "audit_applicationmanagement", "graph_activity"):
        rendered = render_kql(load_kql(name, config), parameters)
        assert "{" not in rendered.replace("{app_filter}", "")


def test_missing_kql_template_lists_the_available_ones() -> None:
    """Asking for a template that does not exist says which do."""
    from entrascope.config import ConfigError, load_config, load_kql

    with pytest.raises(ConfigError) as raised:
        load_kql("no_such_template", load_config())
    assert "signins_failures" in str(raised.value)


def test_render_kql_reports_a_missing_parameter() -> None:
    """A template rendered without a parameter says which one is missing."""
    from entrascope.config import ConfigError, render_kql

    with pytest.raises(ConfigError) as raised:
        render_kql("take {row_limit}", {})
    assert "row_limit" in str(raised.value)


def test_a_quote_cannot_escape_a_kql_literal() -> None:
    """The templates place values inside quotes, and KQL says more than a filter."""
    from entrascope.config import kql_literal

    assert kql_literal('x" or 1==1 or "') == 'x\\" or 1==1 or \\"'
    assert kql_literal("back\\slash") == "back\\\\slash"


def test_numbers_stay_numbers_in_a_query() -> None:
    """A template expecting a row count must not be handed a fragment of query."""
    from entrascope.config import kql_parameter

    assert kql_parameter(50) == 50
    assert kql_parameter(True) == 1
    assert kql_parameter("50; drop") == "50; drop"


def test_rendering_escapes_every_value() -> None:
    """Escaping happens where the query is built, not at the call sites."""
    from entrascope.config import render_kql

    rendered = render_kql(
        'take {row_limit} | where App == "{app}"',
        {"row_limit": 5, "app": 'a" or Table | project x, "'},
    )
    assert rendered.count('"') == 2 + rendered.count('\\"')
    assert "| project" in rendered
    assert "or Table \\| project" not in rendered


def test_control_characters_never_reach_a_query() -> None:
    """A newline in a value would let it start a line of its own."""
    from entrascope.config import kql_literal

    assert kql_literal("a\nb\x00c") == "abc"


def test_the_configuration_ships_inside_the_package() -> None:
    """An installed entrascope must carry its own configuration.

    The repository directory is not there after a pip install, so the packaged
    copy is what an installed tool reads.
    """
    from entrascope.config import PACKAGED_CONFIG_DIRNAME, candidate_directories

    candidates = [str(path) for path in candidate_directories()]
    assert any(PACKAGED_CONFIG_DIRNAME in path for path in candidates)


def test_the_wheel_is_told_to_carry_it() -> None:
    """The mapping that puts it there is easy to lose in a packaging change."""
    import tomllib

    from tests.conftest import REPO_ROOT

    packaging = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    wheel = packaging["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert wheel["force-include"]["config"] == "entrascope/_config"
    assert "src/entrascope/py.typed" in wheel["artifacts"]


def test_every_configuration_file_is_carried() -> None:
    """A file added to the repository but not shipped fails at run time."""
    from tests.conftest import CONFIG_ROOT

    expected = {path.name for path in CONFIG_ROOT.glob("*.yaml")}
    assert expected == set(EXPECTED_FILES) | {
        "error-codes.yaml",
        "capabilities.yaml",
        "server.yaml",
    }


def test_a_directory_of_your_own_layers_over_the_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One file changed must not mean every other file copied.

    A release that adds a setting has to work with a file written before that
    setting existed, or every upgrade becomes a merge.
    """
    from entrascope.config import build_config, clear_cache

    mine = tmp_path / "entrascope"
    mine.mkdir(parents=True)
    (mine / "credentials.yaml").write_text(
        (CONFIG_ROOT / "credentials.yaml")
        .read_text()
        .replace("provisioner-credentials.json", "somewhere-else.json")
    )
    monkeypatch.setattr("entrascope.config.user_config_dir", lambda home=None: mine)
    monkeypatch.setattr("entrascope.config.defaults_directory", lambda: CONFIG_ROOT)
    clear_cache()
    config = build_config(mine)
    assert config.credentials.file.filename == "somewhere-else.json"
    assert config.endpoints.graph.base_url
    assert len(config.error_codes.errors) > 10
    assert config.defaults_root == CONFIG_ROOT
    clear_cache()


def test_a_setting_added_by_a_release_reaches_an_older_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole point of layering rather than replacing."""
    from entrascope.config import build_config, clear_cache

    mine = tmp_path / "entrascope"
    mine.mkdir(parents=True)
    # A file from before update_check existed.
    (mine / "logging.yaml").write_text("level: DEBUG\n")
    monkeypatch.setattr("entrascope.config.user_config_dir", lambda home=None: mine)
    monkeypatch.setattr("entrascope.config.defaults_directory", lambda: CONFIG_ROOT)
    clear_cache()
    config = build_config(mine)
    assert config.logging.level == "DEBUG"
    assert config.logging.update_check.interval_hours
    assert config.logging.redaction.keys
    clear_cache()


def test_merging_replaces_a_list_whole() -> None:
    """Half of somebody's list and half of ours would be nobody's list."""
    from entrascope.config import merge

    merged = merge(
        {"a": {"b": 1, "c": 2}, "list": [1, 2, 3]},
        {"a": {"c": 9}, "list": [7]},
    )
    assert merged == {"a": {"b": 1, "c": 9}, "list": [7]}


def test_a_directory_named_explicitly_stands_alone(tmp_path: Path) -> None:
    """Naming one means that one, not that one plus whatever we ship."""
    from entrascope.config import layered_over_defaults

    assert layered_over_defaults(tmp_path) is None


def test_the_search_prefers_your_directory_to_the_packaged_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Otherwise an upgrade would silently take the edits back."""
    from entrascope.config import (
        candidate_directories,
        packaged_config_dir,
        user_config_dir,
    )

    order = list(candidate_directories())
    assert order.index(user_config_dir()) < order.index(packaged_config_dir())


def test_a_kql_template_falls_back_to_the_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Somebody changing one setting has not signed up to carry the queries."""
    from entrascope.config import build_config, clear_cache, load_kql

    mine = tmp_path / "entrascope"
    mine.mkdir(parents=True)
    (mine / "credentials.yaml").write_text(
        (CONFIG_ROOT / "credentials.yaml").read_text()
    )
    monkeypatch.setattr("entrascope.config.user_config_dir", lambda home=None: mine)
    monkeypatch.setattr("entrascope.config.defaults_directory", lambda: CONFIG_ROOT)
    clear_cache()
    config = build_config(mine)
    assert "SigninLogs" in load_kql("signins_failures", config)
    clear_cache()
