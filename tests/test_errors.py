"""Error code interpretation tests."""

from __future__ import annotations

import pytest

from entrascope.config import Config
from entrascope.errors import (
    explain,
    explain_api_error,
    find_aadsts,
    known_codes,
    search,
)
from entrascope.models import ApiError


def test_error_mapping(config: Config) -> None:
    """A configured code maps to its meaning, remediation and documentation."""
    explanation = explain("AADSTS7000215", config)
    assert explanation.known
    assert "client secret" in explanation.meaning.lower()
    assert "Secret ID" in explanation.likely_cause
    assert explanation.docs_url.startswith("https://learn.microsoft.com/")


def test_error_mapping_is_case_insensitive(config: Config) -> None:
    """A code typed in the wrong case still resolves."""
    assert explain("aadsts50011", config).known


def test_error_mapping_unknown_code(config: Config) -> None:
    """An unrecognised code returns the configured default rather than nothing."""
    explanation = explain("AADSTS999999", config)
    assert not explanation.known
    assert explanation.code == "AADSTS999999"
    assert explanation.docs_url.startswith("https://learn.microsoft.com/")
    assert explanation.remediation


def test_an_embedded_code_is_extracted(config: Config) -> None:
    """A code inside a longer message is found and explained."""
    message = "AADSTS7000222: The provided client secret keys are expired."
    assert explain(message, config).known
    assert find_aadsts(message) == "AADSTS7000222"
    assert find_aadsts("nothing here") == ""


def test_api_error_prefers_the_specific_code(config: Config) -> None:
    """The token endpoint reports a generic code beside a specific one."""
    error = ApiError(
        status=401,
        code="invalid_client",
        message="AADSTS7000215: Invalid client secret provided.",
        source="token",
    )
    explanation = explain_api_error(error, config)
    assert explanation.code == "AADSTS7000215"
    assert explanation.known


def test_api_error_falls_back_to_the_graph_code(config: Config) -> None:
    """A Graph failure with no AADSTS code is explained by its own code."""
    error = ApiError(
        status=403,
        code="Authorization_RequestDenied",
        message="Insufficient privileges to complete the operation.",
        source="graph",
    )
    explanation = explain_api_error(error, config)
    assert explanation.known
    assert "permission" in explanation.remediation.lower()


@pytest.mark.parametrize(
    "code",
    [
        "AADSTS7000215",
        "AADSTS7000222",
        "AADSTS700016",
        "AADSTS50011",
        "AADSTS650057",
        "AADSTS90094",
        "AADSTS500011",
        "AADSTS65001",
        "Authorization_RequestDenied",
    ],
)
def test_every_documented_code_is_configured(code: str, config: Config) -> None:
    """Each code the steering document names is present and explained."""
    assert explain(code, config).known


def test_the_permission_traps_are_covered(config: Config) -> None:
    """The permission traps beyond AADSTS are explained too."""
    for code in (
        "Application_ReadWrite_OwnedBy_Insufficient",
        "Users_Cannot_Register_Applications",
        "Restricted_Management_Administrative_Unit",
        "Missing_Admin_Consent",
    ):
        assert explain(code, config).known


def test_owned_by_explanation_names_the_owner_trap(config: Config) -> None:
    """Adding an owner always needs the broader permission, and the text says so."""
    explanation = explain("Application_ReadWrite_OwnedBy_Insufficient", config)
    assert "Application.ReadWrite.All" in explanation.remediation


def test_known_codes_are_listed(config: Config) -> None:
    """Every configured code can be enumerated for the CLI."""
    codes = known_codes(config)
    assert "AADSTS50011" in codes
    assert codes == tuple(sorted(codes))


def test_search_finds_by_code_and_by_meaning(config: Config) -> None:
    """Searching matches a code fragment or the meaning text."""
    assert any(item.code == "AADSTS50011" for item in search("50011", config))
    assert any("secret" in item.meaning.lower() for item in search("secret", config))
    assert search("no such thing at all", config) == ()


@pytest.mark.parametrize(
    "code",
    [
        "AADSTS5002710",
        "AADSTS700024",
        "Microsoft.Online.Workflows.ValidationException",
        "Microsoft.Online.Workflows.EntitlementValidationException",
    ],
)
def test_codes_seen_against_a_real_tenant_are_explained(
    code: str, config: Config
) -> None:
    """Every code an end to end run actually produced has an explanation.

    These were observed driving the flows against a tenant, not guessed at.
    """
    explanation = explain(code, config)
    assert explanation.known
    assert explanation.remediation
    assert explanation.docs_url.startswith("https://learn.microsoft.com/")


def test_the_client_assertion_codes_point_at_the_certificate(config: Config) -> None:
    """A malformed assertion and an expired one need different remediation."""
    assert "thumbprint" in explain("AADSTS5002710", config).remediation
    assert "clock" in explain("AADSTS700024", config).remediation


def test_the_two_workflow_exceptions_are_told_apart(config: Config) -> None:
    """One is a licence, the other is the wrong object. They read differently."""
    licence = explain(
        "Microsoft.Online.Workflows.EntitlementValidationException", config
    )
    invalid = explain("Microsoft.Online.Workflows.ValidationException", config)
    assert "licence" in licence.remediation.lower()
    assert "registration" in invalid.remediation
