"""Preflight check tests, including capability detection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jwt
import pytest
import responses

from entrascope.capabilities import (
    capability_results,
    decode_claims,
    diagnostic_settings_url,
    enabled_categories,
    grant_command,
    licence_tier,
    missing_permissions,
    required_permissions,
    tier_satisfies,
)
from entrascope.config import Config
from entrascope.doctor import (
    check_authorisation,
    check_credential_storage,
    check_diagnostics,
    check_licence,
    check_network,
    check_token,
    run_checks,
)
from entrascope.models import AuthContext
from tests.conftest import SENTINEL_SECRET
from tests.test_credentials import write_credentials

ROOT = "https://graph.microsoft.com/v1.0"
ARM = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings"

ALL_CATEGORIES = (
    "AuditLogs",
    "SignInLogs",
    "NonInteractiveUserSignInLogs",
    "ServicePrincipalSignInLogs",
    "ManagedIdentitySignInLogs",
    "ProvisioningLogs",
    "MicrosoftGraphActivityLogs",
)


def make_token(**claims: Any) -> str:
    """Mint an unsigned token carrying the claims a check reads."""
    return jwt.encode(claims, key="", algorithm="none")


def application_context(
    client_id: str = "11111111-1111-1111-1111-111111111111",
) -> AuthContext:
    """Return an application identity context."""
    return AuthContext(
        source="file",
        identity_kind="application",
        tenant_id="22222222-2222-2222-2222-222222222222",
        client_id=client_id,
        description="client credentials from the credential file",
    )


def delegated_context() -> AuthContext:
    """Return a delegated identity context, as an Azure CLI session yields."""
    return AuthContext(
        source="azure-cli",
        identity_kind="delegated",
        tenant_id=None,
        client_id=None,
        description="the signed in Azure CLI session",
    )


def diagnostic_payload(categories: tuple[str, ...]) -> dict[str, Any]:
    """Build an Azure Resource Manager diagnostic settings response."""
    return {
        "value": [
            {
                "id": "/providers/microsoft.aadiam/diagnosticSettings/entrascope",
                "name": "entrascope",
                "properties": {
                    "workspaceId": "/subscriptions/x/workspaces/y",
                    "logs": [
                        {"category": name, "enabled": True} for name in categories
                    ],
                },
            }
        ]
    }


def test_decode_claims_reads_an_unsigned_token() -> None:
    """Claims are read without verification, because the authority just issued them."""
    claims = decode_claims(make_token(roles=["Application.Read.All"], tid="abc"))
    assert claims["roles"] == ["Application.Read.All"]
    assert decode_claims("not a token") == {}


def test_missing_permissions_reads_the_token_not_a_table(config: Config) -> None:
    """What the tenant granted is read from the token itself."""
    granted = [permission.name for permission in required_permissions(config)]
    assert missing_permissions(decode_claims(make_token(roles=granted)), config) == ()
    partial = decode_claims(make_token(roles=granted[:2]))
    assert len(missing_permissions(partial, config)) == 2


def test_grant_command_names_the_app_role_ids(config: Config) -> None:
    """A failure prints the exact command, with the identifiers from configuration."""
    missing = required_permissions(config)
    command = grant_command(missing, config, "abc")
    assert "az ad app permission add --id abc" in command
    assert "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role" in command
    assert "admin-consent" in command
    assert grant_command((), config) == ""


def test_licence_tier_is_read_from_the_service_plans(config: Config) -> None:
    """The tier is observed, not asserted."""
    premium = [{"servicePlans": [{"servicePlanName": "AAD_PREMIUM_P2"}]}]
    standard = [{"servicePlans": [{"servicePlanName": "AAD_PREMIUM"}]}]
    assert licence_tier(premium, config) == "P2"
    assert licence_tier(standard, config) == "P1"
    assert licence_tier([], config) == "Free"
    assert licence_tier([{"servicePlans": [{}]}], config) == "Free"


def test_tier_comparison(config: Config) -> None:
    """A higher tier satisfies a lower requirement."""
    assert tier_satisfies("P2", "P1", config)
    assert not tier_satisfies("Free", "P1", config)
    assert tier_satisfies("Free", None, config)


def test_enabled_categories_are_read_from_the_settings() -> None:
    """Only categories actually enabled are counted."""
    payload = {
        "value": [
            {
                "properties": {
                    "logs": [
                        {"category": "AuditLogs", "enabled": True},
                        {"category": "SignInLogs", "enabled": False},
                    ]
                }
            },
            {"nonsense": True},
        ]
    }
    assert enabled_categories(payload) == ("AuditLogs",)
    assert enabled_categories({}) == ()


def test_diagnostic_settings_url_uses_its_own_api_version(config: Config) -> None:
    """The Entra diagnostic settings provider has its own API version."""
    assert "api-version=2017-04-01-preview" in diagnostic_settings_url(config)


def test_check_network_reports_the_proxy_and_the_certificate_authority(
    config: Config,
) -> None:
    """The network check reports what is in force rather than judging it."""
    result = check_network(config)
    assert result.passed
    assert "TLS verified against" in result.detail


def test_check_network_fails_when_verification_is_disabled(config: Config) -> None:
    """Disabling verification is reported as a failure with remediation."""
    network = config.retry.network.model_copy(update={"verify_tls": False})
    disabled = config.model_copy(
        update={"retry": config.retry.model_copy(update={"network": network})}
    )
    result = check_network(disabled)
    assert not result.passed
    assert "verify_tls" in result.remediation


def test_doctor_missing_permission(config: Config) -> None:
    """A missing permission is named, with the command that grants it."""
    claims = decode_claims(make_token(roles=["Application.Read.All"]))
    result, held = check_authorisation(config, claims, application_context())
    assert not result.passed
    assert "AuditLog.Read.All" in result.detail
    assert "az ad app permission add" in result.remediation
    assert result.docs_url.startswith("https://learn.microsoft.com/")
    assert held == ("Application.Read.All",)


def test_doctor_pass_on_a_fully_granted_token(config: Config) -> None:
    """A token carrying everything passes and lists what it holds."""
    granted = [permission.name for permission in required_permissions(config)]
    claims = decode_claims(make_token(roles=granted))
    result, _ = check_authorisation(config, claims, application_context())
    assert result.passed
    assert "AuditLog.Read.All" in result.detail


def test_doctor_azure_cli_delegated_checks(config: Config) -> None:
    """A delegated session is checked against scopes and directory roles."""
    claims = decode_claims(make_token(scp="User.Read"))
    result, held = check_authorisation(config, claims, delegated_context())
    assert not result.passed
    assert "Global Reader" in result.remediation
    assert "az ad app permission add" not in result.remediation
    assert held == ("User.Read",)


def test_doctor_free_tier_says_what_it_costs(config: Config) -> None:
    """A Free tenant is told which capabilities need P1 or P2."""
    result, tier = check_licence(config, [])
    assert tier == "Free"
    assert "P1 or P2" in result.detail


def test_doctor_missing_diagnostics(config: Config) -> None:
    """Each missing category names the remediation and the documentation."""
    results = check_diagnostics(config, ["AuditLogs"])
    passed = [item for item in results if item.passed]
    failed = [item for item in results if not item.passed]
    assert [item.check for item in passed] == ["diagnostic category AuditLogs"]
    assert len(failed) == 6
    signin = next(item for item in failed if "SignInLogs" in item.check)
    assert "Security Administrator" in signin.remediation
    assert signin.docs_url.startswith("https://learn.microsoft.com/")


def test_doctor_reports_a_diagnostics_read_failure(config: Config) -> None:
    """Being unable to read the settings is itself reported, with the reason."""
    results = check_diagnostics(config, (), error="arm returned 403 Forbidden: no")
    assert len(results) == 1
    assert not results[0].passed
    assert "Security Administrator" in results[0].remediation


def test_capability_results_combine_licence_and_diagnostics(config: Config) -> None:
    """A capability needs its category, its tier and its permission together."""
    granted = [permission.name for permission in required_permissions(config)]
    everything = capability_results(
        config, tier="P2", categories=ALL_CATEGORIES, held_permissions=granted
    )
    assert all(item.passed for item in everything)

    nothing = capability_results(
        config, tier="Free", categories=(), held_permissions=[]
    )
    failed = [item for item in nothing if not item.passed]
    assert any("is not exported" in item.detail for item in failed)
    assert any("Free" in item.detail for item in failed)
    assert any("is not granted" in item.detail for item in failed)


def test_credential_storage_is_skipped_for_a_delegated_source(config: Config) -> None:
    """An Azure CLI session needs no credential file, and the report says so."""
    results = check_credential_storage(config, "azure-cli")
    assert results[0].passed
    assert "no credential file" in results[0].detail


def test_token_acquisition_failure_is_reported(config: Config) -> None:
    """A refusal by the authority is a failed check, not a stack trace."""

    # framework contract: azure-core defines the credential shape.
    class Refusing:
        def get_token(self, *scopes: str, **kwargs: Any) -> Any:
            raise RuntimeError("AADSTS7000215: Invalid client secret provided.")

    result, token = check_token(config, Refusing(), application_context())
    assert not result.passed
    assert token == ""
    assert "AADSTS7000215" in result.remediation


def test_doctor_run_reports_an_authentication_failure(
    tmp_path: Path, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no usable source, the run stops early and says how to fix it."""
    monkeypatch.setattr("entrascope.credentials.shutil.which", lambda _: None)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    results = run_checks(config)
    assert any(not item.passed for item in results)
    assert any("az login" in item.remediation for item in results)


@responses.activate
def test_doctor_end_to_end_against_a_healthy_tenant(
    tmp_path: Path, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fully configured tenant passes every check."""
    write_credentials(tmp_path, config=config)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    granted = [permission.name for permission in required_permissions(config)]
    token = make_token(roles=granted, tid="22222222-2222-2222-2222-222222222222")

    # framework contract: azure-core defines the credential and token shapes.
    class Token:
        def __init__(self) -> None:
            self.token = token
            self.expires_on = 4_102_444_800

    class Credential:
        def get_token(self, *scopes: str, **kwargs: Any) -> Any:
            return Token()

    monkeypatch.setattr(
        "entrascope.credentials.build_client_secret_credential",
        lambda credential, verify=True: Credential(),
    )
    responses.add(
        responses.GET,
        f"{ROOT}/subscribedSkus",
        json={"value": [{"servicePlans": [{"servicePlanName": "AAD_PREMIUM_P2"}]}]},
        status=200,
    )
    responses.add(
        responses.GET, ARM, json=diagnostic_payload(ALL_CATEGORIES), status=200
    )
    results = run_checks(config, requested="file")
    failed = [item for item in results if not item.passed]
    assert not failed, [item.detail for item in failed]
    assert any(item.check == "authentication source" for item in results)


@responses.activate
def test_doctor_never_reveals_the_secret(
    tmp_path: Path, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No check output can carry the secret, whatever failed."""
    write_credentials(tmp_path, config=config, file_mode=0o644)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    results = run_checks(config, requested="file")
    assert SENTINEL_SECRET not in json.dumps([item._asdict() for item in results])
