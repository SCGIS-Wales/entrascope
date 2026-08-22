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
