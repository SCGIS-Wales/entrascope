"""Identity report tests: who entrascope is, and what bounds it."""

from __future__ import annotations

from typing import Any

import jwt
import responses

from entrascope.config import Config
from entrascope.http import build_session
from entrascope.identity import (
    ROLE_KIND,
    UNIT_KIND,
    conditional_access,
    group_details,
    membership,
    reachable_tenants,
    safely,
    service_principal_identity,
    signed_in_user,
    tenant_details,
    whoami,
)
from entrascope.models import ApiCallError, ApiError, AuthContext

#: The OData types Microsoft Graph reports for each kind of membership, and the
#: null app role identifier. Both live in config/fields.yaml; they are repeated
#: here so the fixtures look like what Graph actually sends.
GROUP_TYPE = "#microsoft.graph.group"
ROLE_TYPE = "#microsoft.graph.directoryRole"
UNIT_TYPE = "#microsoft.graph.administrativeUnit"
NO_APP_ROLE = "00000000-0000-0000-0000-000000000000"
GROUP_KIND = "group"

ROOT = "https://graph.microsoft.com/v1.0"
ARM = "https://management.azure.com/tenants"
TENANT = "bc96f6fe-1111-1111-1111-111111111111"


# framework contract: azure-core defines the credential and token shapes.
class Token:
    def __init__(self, value: str) -> None:
        self.token = value
        self.expires_on = 4_102_444_800


class Credential:
    def __init__(self, claims: dict[str, Any]) -> None:
        self.value = jwt.encode(claims, key="", algorithm="none")

    def get_token(self, *scopes: str, **kwargs: Any) -> Token:
        return Token(self.value)


def delegated() -> AuthContext:
    """Return a delegated identity context."""
    return AuthContext(
        source="azure-cli",
        identity_kind="delegated",
        tenant_id=None,
        client_id=None,
        description="the signed in Azure CLI session",
    )


def application(client_id: str = "aaaaaaaa-1111-1111-1111-111111111111") -> AuthContext:
    """Return an application identity context."""
    return AuthContext(
        source="file",
        identity_kind="application",
        tenant_id=TENANT,
        client_id=client_id,
        description="a client secret from the credential file",
    )


def register_tenant() -> None:
    """Register the tenant lookup."""
    responses.add(
        responses.GET,
        f"{ROOT}/organization",
        json={
            "value": [
                {
                    "id": TENANT,
                    "displayName": "Default Directory",
                    "countryLetterCode": "NL",
                    "verifiedDomains": [
                        {"name": "example.onmicrosoft.com", "isDefault": True}
                    ],
                }
            ]
        },
        status=200,
    )


def test_safely_records_a_refusal_rather_than_failing() -> None:
    """One lookup being refused must not empty the whole report."""
    notes: list[str] = []

    def refuse() -> None:
        raise ApiCallError(ApiError(status=403, code="no", message="denied"))

    assert safely(refuse, notes, "Something", default=()) == ()
    assert "Something" in notes[0]
    assert safely(lambda: "fine", notes, "Other", default="") == "fine"
    assert len(notes) == 1


def test_membership_separates_the_kinds(config: Config) -> None:
    """Roles, groups and administrative units arrive from one call together."""
    rows: list[dict[str, Any]] = [
        {"@odata.type": ROLE_TYPE, "displayName": "Global Reader"},
        {"@odata.type": GROUP_TYPE, "displayName": "Engineers"},
        {"@odata.type": UNIT_TYPE, "displayName": "Northern region"},
        {"@odata.type": GROUP_TYPE, "id": "no-name"},
    ]
    assert membership(rows, ROLE_KIND, config) == ["Global Reader"]
    assert membership(rows, UNIT_KIND, config) == ["Northern region"]
    assert membership(rows, GROUP_KIND, config) == ["Engineers", "no-name"]


def test_security_groups_are_named_rather_than_counted(config: Config) -> None:
    """A count of groups tells nobody which group carries the access."""
    rows: list[dict[str, Any]] = [
        {
            "@odata.type": GROUP_TYPE,
            "id": "group-1",
            "displayName": "Platform engineers",
            "securityEnabled": True,
        },
        {
            "@odata.type": GROUP_TYPE,
            "id": "group-2",
            "displayName": "Everyone",
            "securityEnabled": False,
        },
        {
            "@odata.type": GROUP_TYPE,
            "id": "group-3",
            "displayName": "Joiners",
            "securityEnabled": True,
            "membershipRule": 'user.department -eq "Platform"',
        },
    ]
    groups = group_details(rows, config)
    assert [item["display_name"] for item in groups] == [
        "Platform engineers",
        "Joiners",
    ]
    assert groups[0]["dynamic"] is False
    assert groups[1]["dynamic"] is True


@responses.activate
def test_the_tenant_is_named_as_well_as_numbered(config: Config) -> None:
    """A tenant identifier alone tells nobody which tenant they are in."""
    register_tenant()
    details = tenant_details(build_session(config), config, [])
    assert details["tenant_id"] == TENANT
    assert details["display_name"] == "Default Directory"
    assert details["default_domain"] == "example.onmicrosoft.com"


@responses.activate
def test_a_delegated_identity_reports_its_roles_and_bounds(config: Config) -> None:
    """Directory roles decide what a delegated session can read."""
    responses.add(
        responses.GET,
        f"{ROOT}/me",
        json={
            "id": "0a0a0a0a-1111-1111-1111-111111111111",
            "displayName": "An Engineer",
            "userPrincipalName": "engineer@example.invalid",
        },
        status=200,
    )
    responses.add(
        responses.GET,
        f"{ROOT}/me/memberOf",
        json={
            "value": [
                {"@odata.type": ROLE_TYPE, "displayName": "Global Reader"},
                {"@odata.type": UNIT_TYPE, "displayName": "Northern region"},
                {"@odata.type": GROUP_TYPE, "displayName": "Engineers"},
            ]
        },
        status=200,
    )
    report = signed_in_user(build_session(config), config, [])
    assert report["directory_roles"] == ["Global Reader"]
    assert report["administrative_units"] == ["Northern region"]
    assert report["group_count"] == 1


@responses.activate
def test_an_application_identity_reports_what_it_was_granted(config: Config) -> None:
    """An assignment with no role is access to the application, nothing more."""
    responses.add(
        responses.GET,
        f"{ROOT}/servicePrincipals(appId='abc')",
        json={
            "value": [
                {"id": "sp-1", "displayName": "A service", "accountEnabled": True}
            ]
        },
        status=200,
    )
    responses.add(
        responses.GET,
        f"{ROOT}/servicePrincipals/sp-1/memberOf",
        json={
            "value": [{"@odata.type": ROLE_TYPE, "displayName": "Directory Readers"}]
        },
        status=200,
    )
    responses.add(
        responses.GET,
        f"{ROOT}/servicePrincipals/sp-1/appRoleAssignments",
        json={
            "value": [
                {"resourceDisplayName": "Microsoft Graph", "appRoleId": NO_APP_ROLE},
                {"resourceDisplayName": "Microsoft Graph", "appRoleId": "9a5d68dd"},
            ]
        },
        status=200,
    )
    report = service_principal_identity(build_session(config), config, "abc", [])
    assert report["display_name"] == "A service"
    assert report["directory_roles"] == ["Directory Readers"]
    assignments = report["granted_app_role_assignments"]
    assert "carrying no permission" in assignments[0]["meaning"]
    assert assignments[1]["meaning"] == "an application permission"


@responses.activate
def test_an_absent_service_principal_is_not_an_error(config: Config) -> None:
    """An application registration without its service principal still reports."""
    responses.add(
        responses.GET,
        f"{ROOT}/servicePrincipals(appId='abc')",
        json={"value": []},
        status=200,
    )
    assert service_principal_identity(build_session(config), config, "abc", []) == {}


@responses.activate
def test_conditional_access_is_summarised_not_evaluated(config: Config) -> None:
    """Whether a policy applies is decided by Entra, not here, and it says so."""
    responses.add(
        responses.GET,
        f"{ROOT}/identity/conditionalAccess/policies",
        json={
            "value": [
                {
                    "displayName": "Require multifactor",
                    "state": "enabled",
                    "conditions": {
                        "applications": {"includeApplications": ["All"]},
                        "users": {"excludeUsers": ["someone"]},
                    },
                },
                {"displayName": "Off for now", "state": "disabled", "conditions": {}},
            ]
        },
        status=200,
    )
    summary = conditional_access(build_session(config), config, [])
    assert summary["policy_count"] == 2
    assert summary["enabled_count"] == 1
    assert summary["policies"][0]["applications"] == {"includeApplications": ["All"]}
    assert "decided at the time" in summary["note"]


@responses.activate
def test_unreadable_policies_say_what_they_need(config: Config) -> None:
    """A refusal names the permission rather than showing an empty list."""
    responses.add(
        responses.GET,
        f"{ROOT}/identity/conditionalAccess/policies",
        json={"error": {"code": "Authorization_RequestDenied", "message": "no"}},
        status=403,
    )
    notes: list[str] = []
    summary = conditional_access(build_session(config), config, notes)
    assert "Policy.Read.All" in summary["note"]
    assert notes


@responses.activate
def test_reachable_tenants_come_from_resource_manager(config: Config) -> None:
    """Microsoft Graph does not know which tenants an identity can reach."""
    responses.add(
        responses.GET,
        ARM,
        json={
            "value": [
                {
                    "tenantId": TENANT,
                    "displayName": "Default Directory",
                    "defaultDomain": "example.onmicrosoft.com",
                }
            ]
        },
        status=200,
    )
    tenants = reachable_tenants(config, Credential({}), [])
    assert tenants[0]["tenant_id"] == TENANT


@responses.activate
def test_a_resource_manager_refusal_is_a_note(config: Config) -> None:
    """An identity with no Azure access still gets the rest of the report."""
    responses.add(responses.GET, ARM, json={"error": {"code": "no"}}, status=403)
    notes: list[str] = []
    assert reachable_tenants(config, Credential({}), notes) == []
    assert notes


@responses.activate
def test_the_whole_report_for_a_delegated_session(config: Config) -> None:
    """Everything an engineer needs to know about the identity in one place."""
    register_tenant()
    responses.add(responses.GET, f"{ROOT}/me", json={"id": "u1"}, status=200)
    responses.add(responses.GET, f"{ROOT}/me/memberOf", json={"value": []}, status=200)
    responses.add(
        responses.GET,
        f"{ROOT}/identity/conditionalAccess/policies",
        json={"value": []},
        status=200,
    )
    responses.add(responses.GET, ARM, json={"value": []}, status=200)
    credential = Credential(
        {"tid": TENANT, "scp": "User.Read Directory.Read.All", "oid": "u1"}
    )
    report = whoami(build_session(config), config, credential, delegated())
    assert report["authentication"]["source"] == "azure-cli"
    assert report["tenant"]["display_name"] == "Default Directory"
    assert report["permissions"]["delegated_scopes"] == [
        "User.Read",
        "Directory.Read.All",
    ]
    assert report["token"]["tid"] == TENANT
    assert "conditional_access" in report


@responses.activate
def test_the_policies_can_be_skipped(config: Config) -> None:
    """A tenant without Policy.Read.All should not have to wait for a refusal."""
    register_tenant()
    responses.add(
        responses.GET,
        f"{ROOT}/servicePrincipals(appId='aaaaaaaa-1111-1111-1111-111111111111')",
        json={"value": []},
        status=200,
    )
    responses.add(responses.GET, ARM, json={"value": []}, status=200)
    report = whoami(
        build_session(config),
        config,
        Credential({"roles": ["Application.Read.All"]}),
        application(),
        with_policies=False,
    )
    assert "conditional_access" not in report
    assert report["permissions"]["application_permissions"] == ["Application.Read.All"]
