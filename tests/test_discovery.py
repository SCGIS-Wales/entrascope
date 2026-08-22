"""Discovery projection and classification tests.

Every test here works from a fixture. Projection and classification never reach
the network, so nothing is mocked beyond the two Graph collections.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import pytest
import responses

from entrascope.config import Config
from entrascope.discovery import (
    audience_label,
    classify_application,
    credential_state,
    discover_applications,
    discover_service_principals,
    parse_timestamp,
    pluck,
    project_application,
    project_credentials,
    project_granted_permissions,
    project_service_principal,
    strings,
)
from entrascope.http import build_session
from entrascope.models import RedirectUris
from tests.conftest import FIXTURE_ROOT, load_fixture

ROOT = "https://graph.microsoft.com/v1.0"
NOW = datetime(2026, 8, 22, tzinfo=UTC)

#: Fixture identifiers are deliberately built from a repeated digit or letter so
#: that no real tenant identifier can be committed to a public repository.
SYNTHETIC = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def by_name(rows: Any, name: str) -> Any:
    """Return the projected row with one display name."""
    return next(row for row in rows if row.display_name == name)


def well_known_identifiers(config: Config) -> set[str]:
    """Return the Microsoft identifiers that are public constants, not tenant data."""
    return {
        config.endpoints.graph.resource_app_id,
        *(role.app_role_id for role in config.capabilities.graph_permissions),
        *(role.template_id for role in config.capabilities.directory_roles),
    }


def test_fixtures_carry_no_real_identifier(config: Config) -> None:
    """Every fixture identifier is synthetic, because the repository is public."""
    pattern = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    )
    allowed_real = well_known_identifiers(config)
    for path in FIXTURE_ROOT.glob("*.json"):
        for found in pattern.findall(path.read_text()):
            if found in allowed_real:
                continue
            segments = found.split("-")
            assert any(len(set(segment)) == 1 for segment in segments), (
                f"{path.name} carries {found}, which does not look synthetic."
            )


def test_pluck_walks_a_dotted_path() -> None:
    """Nested Graph properties are read by dotted path from the field mapping."""
    assert pluck({"api": {"version": 2}}, "api.version") == 2
    assert pluck({"api": {}}, "api.version") is None
    assert pluck({"api": "not a mapping"}, "api.version") is None


def test_strings_coerces_every_shape() -> None:
    """A Graph value becomes a tuple of strings whatever shape it arrives in."""
    assert strings(None) == ()
    assert strings("one") == ("one",)
    assert strings(["a", "b"]) == ("a", "b")
    assert strings(7) == ("7",)


def test_parse_timestamp_tolerates_the_trailing_zulu() -> None:
    """Graph timestamps parse whether they end in Z or an offset."""
    assert parse_timestamp("2026-01-01T00:00:00Z") is not None
    assert parse_timestamp("not a date") is None
    assert parse_timestamp("") is None


def test_credential_expiry_states(config: Config) -> None:
    """A credential is valid, expiring or expired against the configured window."""
    window = config.fields.expiry.warning_days
    assert credential_state(datetime(2027, 1, 1, tzinfo=UTC), window, NOW)[0] == "valid"
    soon = credential_state(datetime(2026, 9, 1, tzinfo=UTC), window, NOW)
    assert soon[0] == "expiring"
    gone = credential_state(datetime(2026, 1, 1, tzinfo=UTC), window, NOW)
    assert gone[0] == "expired"
    assert credential_state(None, window, NOW) == ("unknown", None)


def test_credential_expiry_is_flagged_on_a_projection(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """Expired and valid credentials on one application are told apart."""
    summary = project_application(applications[0], config, now=NOW)
    states = {item.display_name: item.state for item in summary.credentials}
    assert states["primary secret"] == "valid"
    assert states["expired secret"] == "expired"
    assert len(summary.expiring()) == 1


def test_certificate_credentials_are_distinguished(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """A key credential is projected as a certificate, not as a secret."""
    summary = project_application(applications[4], config, now=NOW)
    assert [item.kind for item in summary.credentials] == ["certificate"]
    assert summary.credentials[0].state == "expiring"


@pytest.mark.parametrize(
    ("index", "expected"),
    [
        (0, "confidential-client"),
        (1, "single-page-application"),
        (2, "native-or-mobile"),
        (4, "confidential-client"),
    ],
)
def test_discovery_types_for_registrations(
    config: Config, applications: list[dict[str, Any]], index: int, expected: str
) -> None:
    """Each application registration type is classified from its attributes."""
    summary = project_application(applications[index], config, now=NOW)
    assert summary.application_type == expected


def test_workload_identity_federation_is_decisive(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """An application with a federated credential is classified by that first."""
    federated = load_fixture("federated_credentials")["value"]
    summary = project_application(applications[3], config, federated=federated, now=NOW)
    assert summary.application_type == "workload-identity-federation"
    assert summary.federated_credentials[0].subject.startswith("repo:")
    assert summary.federated_credentials[0].audiences


def test_an_application_with_nothing_registered_is_a_public_client() -> None:
    """With no credential and no redirect URI the safest reading is a public client."""
    assert classify_application(RedirectUris(), (), ()) == "public-client"


@pytest.mark.parametrize(
    ("audience", "expected"),
    [
        ("AzureADMyOrg", "this tenant only"),
        ("AzureADMultipleOrgs", "any tenant"),
        ("AzureADandPersonalMicrosoftAccount", "any tenant and personal accounts"),
        ("PersonalMicrosoftAccount", "personal accounts only"),
        ("SomethingNew", "unrecognised audience"),
    ],
)
def test_sign_in_audience_is_described(
    config: Config, audience: str, expected: str
) -> None:
    """Every sign in audience gets a readable description."""
    assert audience_label(audience, config) == expected


def test_requested_permissions_separate_delegated_from_application(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """Scope and Role entries are projected apart, because consent treats them apart."""
    summary = project_application(applications[0], config, now=NOW)
    requested = summary.requested_permissions[0]
    assert requested.resource_app_id == "00000003-0000-0000-c000-000000000000"
    assert len(requested.application) == 1
    assert len(requested.delegated) == 1


def test_owners_are_projected_by_readable_name(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """An owner is named however Graph identifies it."""
    owners = load_fixture("owners")["value"]
    summary = project_application(applications[0], config, owners=owners, now=NOW)
    assert summary.owners == ("Platform Engineering",)


def test_requested_access_token_version_is_kept(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """Token version two matters for the remote server, so it is projected."""
    first = project_application(applications[0], config, now=NOW)
    second = project_application(applications[1], config, now=NOW)
    assert first.requested_access_token_version == 2
    assert second.requested_access_token_version is None


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Confidential web application", "enterprise-application"),
        ("Gallery SAML application", "saml-gallery"),
        ("Bespoke SAML application", "saml-non-gallery"),
        ("aks-cluster-agentpool", "managed-identity"),
        ("Legacy application", "legacy"),
    ],
)
def test_discovery_types_for_enterprise_applications(
    config: Config, service_principals: list[dict[str, Any]], name: str, expected: str
) -> None:
    """Each enterprise application type is classified from its Graph payload."""
    projected = [
        project_service_principal(payload, config, now=NOW)
        for payload in service_principals
    ]
    assert by_name(projected, name).application_type == expected


def test_saml_projection(
    config: Config, service_principals: list[dict[str, Any]]
) -> None:
    """A SAML application carries its reply URLs, entity ids and signing certificate."""
    projected = [
        project_service_principal(payload, config, now=NOW)
        for payload in service_principals
    ]
    gallery = by_name(projected, "Gallery SAML application")
    assert gallery.saml is not None
    assert gallery.saml.is_gallery
    assert gallery.saml.reply_urls
    assert gallery.saml.identifier_uris
    certificate = gallery.saml.signing_certificates[0]
    assert certificate.state in ("expiring", "expired", "valid")

    bespoke = by_name(projected, "Bespoke SAML application")
    assert bespoke.saml is not None
    assert not bespoke.saml.is_gallery


def test_a_non_saml_application_has_no_saml_configuration(
    config: Config, service_principals: list[dict[str, Any]]
) -> None:
    """Projection returns nothing rather than an empty shell."""
    summary = project_service_principal(service_principals[0], config, now=NOW)
    assert summary.saml is None


def test_assignment_required_and_enabled_are_projected(
    config: Config, service_principals: list[dict[str, Any]]
) -> None:
    """Assignment requirement explains a refusal that consent alone cannot."""
    projected = [
        project_service_principal(payload, config, now=NOW)
        for payload in service_principals
    ]
    confidential = by_name(projected, "Confidential web application")
    assert confidential.app_role_assignment_required
    assert not by_name(projected, "Legacy application").account_enabled


def test_granted_permissions_cover_both_kinds() -> None:
    """Delegated scopes are split, and application roles are kept whole."""
    fixture = load_fixture("permission_grants")
    grants = project_granted_permissions(
        fixture["oauth2PermissionGrants"], fixture["appRoleAssignments"]
    )
    delegated = [item for item in grants if item.kind == "delegated"]
    application = [item for item in grants if item.kind == "application"]
    assert {item.value for item in delegated} == {"User.Read", "Directory.Read.All"}
    assert delegated[0].principal == "all users"
    assert len(application) == 1


def test_projection_tolerates_a_sparse_payload(config: Config) -> None:
    """A payload missing every optional property still projects."""
    summary = project_application({"id": "x"}, config, now=NOW)
    assert summary.object_id == "x"
    assert summary.credentials == ()
    assert summary.redirect_uris.total() == 0


def test_project_credentials_ignores_a_malformed_entry(config: Config) -> None:
    """A credential that is not an object is skipped rather than raising."""
    payload = {"passwordCredentials": ["not an object"], "keyCredentials": []}
    assert project_credentials(payload, config, config.fields.application, NOW) == ()


@responses.activate
def test_discover_applications_without_details(config: Config) -> None:
    """With no token, owners and federated credentials are skipped."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json=load_fixture("applications"),
        status=200,
    )
    summaries = discover_applications(build_session(config), config, with_details=False)
    assert len(summaries) == 5
    assert all(summary.owners == () for summary in summaries)


@responses.activate
def test_discover_applications_fetches_details_concurrently(config: Config) -> None:
    """With a token, owners and federated credentials are fetched per application."""
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json=load_fixture("applications"),
        status=200,
    )
    for payload in load_fixture("applications")["value"]:
        object_id = payload["id"]
        responses.add(
            responses.GET,
            f"{ROOT}/applications/{object_id}/owners",
            json=load_fixture("owners"),
            status=200,
        )
        responses.add(
            responses.GET,
            f"{ROOT}/applications/{object_id}/federatedIdentityCredentials",
            json=load_fixture("federated_credentials"),
            status=200,
        )
    summaries = discover_applications(build_session(config), config, lambda: "token")
    assert all(summary.owners for summary in summaries)
    assert all(summary.federated_credentials for summary in summaries)


@responses.activate
def test_discover_service_principals(config: Config) -> None:
    """Enterprise application discovery projects every fixture."""
    responses.add(
        responses.GET,
        f"{ROOT}/servicePrincipals",
        json=load_fixture("service_principals"),
        status=200,
    )
    summaries = discover_service_principals(
        build_session(config), config, with_details=False
    )
    assert len(summaries) == 5
    assert {summary.application_type for summary in summaries} == {
        "enterprise-application",
        "saml-gallery",
        "saml-non-gallery",
        "managed-identity",
        "legacy",
    }


def test_an_application_that_exposes_an_api_is_not_a_client(config: Config) -> None:
    """A resource signs nobody in.

    Calling it a public client, which is what the fallback used to do, sends
    the reader looking for a sign in that never happens.
    """
    payload = {
        "id": "1",
        "appId": "a",
        "displayName": "An API",
        "identifierUris": ["api://a"],
        "api": {"oauth2PermissionScopes": [{"id": "s", "value": "access_as_user"}]},
        "appRoles": [{"id": "r", "value": "Reports.Read"}],
    }
    summary = project_application(payload, config, now=NOW)
    assert summary.application_type == "api-or-resource"
    assert summary.exposes_api is True


def test_a_resource_that_is_also_a_client_is_classified_as_the_client(
    config: Config,
) -> None:
    """An application that exposes an API and signs users in is both.

    The client side is what a sign in failure is about, so that is what the
    type names.
    """
    payload = {
        "id": "1",
        "appId": "a",
        "displayName": "Both",
        "identifierUris": ["api://a"],
        "web": {"redirectUris": ["https://both.example.invalid/cb"]},
    }
    assert project_application(payload, config, now=NOW).application_type == (
        "web-client"
    )


def test_a_web_application_with_no_credential_is_not_confidential(
    config: Config,
) -> None:
    """Confidential means it holds a secret. This one does not."""
    payload = {
        "id": "1",
        "appId": "a",
        "displayName": "No secret",
        "web": {"redirectUris": ["https://web.example.invalid/cb"]},
    }
    assert project_application(payload, config, now=NOW).application_type == (
        "web-client"
    )


def test_a_web_application_with_a_credential_is_confidential(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """And this one does."""
    assert project_application(applications[0], config, now=NOW).application_type == (
        "confidential-client"
    )


def test_a_service_principal_does_not_guess_the_client_type(config: Config) -> None:
    """The registration decides that, and the service principal does not carry it."""
    payload = {
        "id": "1",
        "appId": "a",
        "displayName": "An app",
        "servicePrincipalType": "Application",
    }
    summary = project_service_principal(payload, config, now=NOW)
    assert summary.application_type == "enterprise-application"


def test_exposing_an_api_is_recognised_from_any_of_its_signs(config: Config) -> None:
    """An identifier URI, a role or a scope each mean somebody can call it."""
    from entrascope.discovery import exposes_an_api

    assert exposes_an_api({"identifierUris": ["api://a"]}, config)
    assert exposes_an_api({"appRoles": [{"id": "r"}]}, config)
    assert exposes_an_api({"api": {"oauth2PermissionScopes": [{"id": "s"}]}}, config)
    assert not exposes_an_api({"displayName": "nothing"}, config)
