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

    everything = (*EXPECTED_FILES, "error-codes.yaml", "capabilities.yaml")
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
