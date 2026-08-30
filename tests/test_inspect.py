"""Inspection tests: one application, in full."""

from __future__ import annotations

import re
from typing import Any

import pytest
import responses

from entrascope.config import Config
from entrascope.http import build_session
from entrascope.inspect import (
    as_mapping,
    candidates,
    consent_state,
    exposed_api,
    inspect,
    matching,
    named_permissions,
    permission_names,
    read_catalogue,
    search_gallery,
    urls,
)
from entrascope.models import ApiCallError
from tests.conftest import load_fixture

ROOT = "https://graph.microsoft.com/v1.0"
GRAPH_APP = "00000003-0000-0000-c000-000000000000"


def register(
    *,
    templates: list[dict[str, Any]] | None = None,
    assigned_to: list[dict[str, Any]] | None = None,
    grants: list[dict[str, Any]] | None = None,
    held_roles: list[dict[str, Any]] | None = None,
    member_of: list[dict[str, Any]] | None = None,
) -> None:
    """Register the calls an inspection makes.

    Discovery fetches owners and federated credentials one object at a time
    when a token is supplied, which the command line does, so those are matched
    by pattern. The four collections that say what an application may do and
    who may use it are registered separately, because reading the wrong one of
    them is the mistake these tests exist to catch.
    """
    responses.add(
        responses.GET,
        f"{ROOT}/applications",
        json=load_fixture("applications"),
        status=200,
    )
    responses.add(
        responses.GET,
        f"{ROOT}/servicePrincipals",
        json=load_fixture("service_principals"),
        status=200,
    )
    for pattern, body in (
        (rf"{re.escape(ROOT)}/applications/[^/]+/owners", load_fixture("owners")),
        (
            rf"{re.escape(ROOT)}/applications/[^/]+/federatedIdentityCredentials",
            {"value": []},
        ),
        (rf"{re.escape(ROOT)}/servicePrincipals/[^/]+/owners", {"value": []}),
        (
            rf"{re.escape(ROOT)}/servicePrincipals/[^/]+/appRoleAssignedTo",
            {"value": assigned_to or []},
        ),
        (
            rf"{re.escape(ROOT)}/servicePrincipals/[^/]+/appRoleAssignments",
            {"value": held_roles or []},
        ),
        (
            rf"{re.escape(ROOT)}/servicePrincipals/[^/]+/memberOf",
            {"value": member_of or []},
        ),
    ):
        responses.add(responses.GET, re.compile(pattern), json=body, status=200)
    responses.add(
        responses.GET,
        f"{ROOT}/oauth2PermissionGrants",
        json={"value": grants or []},
        status=200,
    )
    responses.add(
        responses.GET,
        re.compile(rf"{re.escape(ROOT)}/applications/[0-9a-f-]+"),
        json=load_fixture("applications")["value"][0],
        status=200,
    )
    # The enterprise application read on its own. Without this the read is
    # refused, every collection hanging off it is skipped, and a report full of
    # empty sections looks exactly like an application with nothing granted.
    responses.add(
        responses.GET,
        re.compile(rf"{re.escape(ROOT)}/servicePrincipals/[0-9a-f-]+$"),
        json=load_fixture("service_principals")["value"][0],
        status=200,
    )
    responses.add(
        responses.GET,
        re.compile(rf"{re.escape(ROOT)}/servicePrincipals\(appId="),
        json={
            "oauth2PermissionScopes": [
                {"id": "eeee1111-1111-1111-1111-111111111111", "value": "User.Read"}
            ],
            "appRoles": [
                {
                    "id": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
                    "value": "Application.Read.All",
                }
            ],
        },
        status=200,
    )
    if templates is not None:
        responses.add(
            responses.GET,
            f"{ROOT}/applicationTemplates",
            json={"value": templates},
            status=200,
        )


def test_as_mapping_tolerates_anything() -> None:
    """Graph omits a section rather than sending an empty one."""
    assert as_mapping({"a": 1}) == {"a": 1}
    assert as_mapping(None) == {}
    assert as_mapping("not a mapping") == {}


def test_matching_by_name_identifier_and_type(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """An engineer has whichever handle the error message gave them."""
    from entrascope.discovery import project_application

    projected = [project_application(row, config) for row in applications]
    assert len(matching(projected, "confidential")) == 1
    assert len(matching(projected, projected[0].app_id)) == 1
    assert len(matching(projected, projected[0].object_id)) == 1
    assert matching(projected, "", ["single-page-application"])[0].display_name == (
        "Single page application"
    )
    assert matching(projected, "nothing at all") == ()


def test_exposed_api_projects_scopes_and_roles() -> None:
    """What an application offers to others is half of a permission failure."""
    payload = {
        "identifierUris": ["api://x"],
        "api": {
            "requestedAccessTokenVersion": 2,
            "oauth2PermissionScopes": [
                {"value": "access_as_user", "type": "User", "isEnabled": True}
            ],
            "preAuthorizedApplications": [{"appId": "abc"}],
        },
        "appRoles": [{"value": "Reader", "displayName": "Reader", "isEnabled": True}],
    }
    exposed = exposed_api(payload)
    assert exposed["delegated_scopes"][0]["value"] == "access_as_user"
    assert exposed["application_roles"][0]["value"] == "Reader"
    assert exposed["pre_authorized_applications"] == ["abc"]
    assert exposed["requested_access_token_version"] == 2


def test_exposed_api_tolerates_an_empty_application() -> None:
    """A registration with nothing exposed still projects."""
    assert exposed_api({})["delegated_scopes"] == []


def test_consent_state_names_the_gap(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """What was asked for against what was granted is where consent shows up."""
    from entrascope.discovery import project_application, project_service_principal

    application = project_application(applications[0], config)
    principal = project_service_principal({"id": "x"}, config)
    state = consent_state(application, principal)
    assert state["requested_delegated"] == 1
    assert state["requested_application"] == 1
    assert state["admin_consent_granted"] is False
    assert state["admin_consent_complete"] is False
    assert "no consent of any kind" in state["not_consented"][0]["why"]


def test_consent_state_recognises_a_grant(config: Config) -> None:
    """A tenant wide delegated grant is admin consent just as a role is."""
    from entrascope.discovery import project_service_principal
    from entrascope.models import PermissionGrant

    principal = project_service_principal({"id": "x"}, config)._replace(
        granted_permissions=(
            PermissionGrant(
                resource_app_id="r",
                kind="delegated",
                value="User.Read",
                principal="all users",
                consent_type="AllPrincipals",
                admin_consent_recorded=True,
            ),
        )
    )
    assert consent_state(None, principal)["admin_consent_granted"] is True


def test_a_permission_needing_admin_consent_is_named_when_it_lacks_it(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """The whole point: an engineer must be able to see which one is missing."""
    from entrascope.discovery import project_application, project_service_principal
    from entrascope.inspect import PermissionCatalogue, PermissionFact

    application = project_application(applications[0], config)
    requested = application.requested_permissions[0]
    catalogue = PermissionCatalogue(
        by_id={
            requested.delegated[0]: PermissionFact(
                value="User.Read",
                kind="delegated",
                admin_consent_required=False,
                resource="Microsoft Graph",
            ),
            requested.application[0]: PermissionFact(
                value="Application.Read.All",
                kind="application",
                admin_consent_required=True,
                resource="Microsoft Graph",
            ),
        },
        by_value={},
        resource_names={requested.resource_app_id: "Microsoft Graph"},
    )
    state = consent_state(
        application, project_service_principal({"id": "x"}, config), catalogue
    )
    outstanding = state["without_admin_consent"]
    assert [row["permission"] for row in outstanding] == ["Application.Read.All"]
    assert outstanding[0]["resource"] == "Microsoft Graph"
    assert "Application.Read.All" in state["admin_consent_note"]
    # User.Read needs no administrator, so it is missing consent but is not an
    # admin consent problem, and saying otherwise sends somebody to the wrong
    # place.
    assert [row["permission"] for row in state["not_consented"]] == [
        "User.Read",
        "Application.Read.All",
    ]


def test_a_permission_consented_by_one_person_is_told_apart(config: Config) -> None:
    """It works for them and is refused for everybody else, and nothing says so."""
    from entrascope.discovery import project_service_principal
    from entrascope.models import PermissionGrant

    principal = project_service_principal({"id": "x"}, config)._replace(
        granted_permissions=(
            PermissionGrant(
                resource_app_id="r",
                kind="delegated",
                value="Mail.Read",
                principal="person-1",
                consent_type="Principal",
                principal_id="person-1",
                admin_consent_recorded=False,
            ),
        )
    )
    state = consent_state(None, principal)
    assert state["user_consented_only"][0]["value"] == "Mail.Read"
    assert "individual rather than for the tenant" in state["admin_consent_note"]


def test_urls_are_shown_exactly_as_registered(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """A redirect is compared byte for byte, so it is not tidied here."""
    from entrascope.discovery import project_application

    application = project_application(applications[0], config)
    gathered = urls(application, None, {"web": {"logoutUrl": "https://x/logout"}})
    assert gathered["web_redirect_uris"] == ["https://app.example.invalid/callback"]
    assert gathered["logout_url"] == "https://x/logout"


def test_named_permissions_falls_back_to_the_identifier(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """A permission that cannot be resolved is still reported."""
    from entrascope.discovery import project_application

    application = project_application(applications[0], config)
    named = named_permissions(application, {})
    assert named[0]["delegated"] == ["eeee1111-1111-1111-1111-111111111111"]


@responses.activate
def test_permission_names_are_resolved(config: Config) -> None:
    """A bare identifier is no use to anybody reading a report."""
    register()
    resolved = permission_names(build_session(config), config, [GRAPH_APP])
    assert resolved["9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"] == "Application.Read.All"


@responses.activate
def test_permission_names_tolerate_a_refusal(config: Config) -> None:
    """A resource the caller cannot read leaves the identifiers unresolved."""
    responses.add(
        responses.GET,
        re.compile(rf"{re.escape(ROOT)}/servicePrincipals\(appId="),
        json={"error": {"code": "Authorization_RequestDenied", "message": "no"}},
        status=403,
    )
    assert permission_names(build_session(config), config, [GRAPH_APP]) == {}
    assert permission_names(build_session(config), config, [""]) == {}


@responses.activate
def test_inspecting_one_application(config: Config) -> None:
    """Both objects are reported together, because either can be the fault."""
    register()
    report = inspect(build_session(config), config, target="Confidential web")
    assert report["identity"]["display_name"] == "Confidential web application"
    assert report["identity"]["application_type"] == "confidential-client"
    assert report["sign_in"]["audience_meaning"] == "this tenant only"
    assert report["urls"]["web_redirect_uris"]
    assert report["permissions"]["requested"][0]["delegated"] == ["User.Read"]
    assert report["credentials"]
    assert report["portal"]["registration"].startswith("https://portal.azure.com")


@responses.activate
def test_inspecting_reads_consent_rather_than_who_is_assigned(
    config: Config,
) -> None:
    """The two app role collections are different things and were confused.

    appRoleAssignedTo lists who may use the application. appRoleAssignments
    lists the application permissions the application holds. Reading the first
    where the second was meant reported the wrong objects as granted
    permissions and left delegated consent empty, so both are asserted here.
    """
    register(
        grants=[
            {
                "clientId": "sp-1",
                "resourceId": GRAPH_APP,
                "consentType": "AllPrincipals",
                "principalId": None,
                "scope": "User.Read",
            }
        ],
        held_roles=[
            {
                "appRoleId": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
                "resourceId": GRAPH_APP,
                "resourceDisplayName": "Microsoft Graph",
                "principalDisplayName": "Confidential web application",
            }
        ],
        assigned_to=[
            {
                "principalId": "group-1",
                "principalDisplayName": "Platform engineers",
                "principalType": "Group",
                "appRoleId": "00000000-0000-0000-0000-000000000000",
            }
        ],
    )
    report = inspect(build_session(config), config, target="Confidential web")
    consent = report["permissions"]["consent"]
    assert consent["granted_delegated"] == ["User.Read"]
    assert consent["granted_application"] == ["Application.Read.All"]
    assert consent["admin_consent_complete"] is True
    assert consent["without_admin_consent"] == []
    # The group is an assignment, not a permission. It must not appear as one.
    assert "Platform engineers" not in str(consent["granted"])
    assert report["access"]["security_groups"][0]["principal_display_name"] == (
        "Platform engineers"
    )


@responses.activate
def test_inspecting_names_the_permission_nobody_consented_to(
    config: Config,
) -> None:
    """A missing admin consent must be readable off the output, not inferred."""
    register()
    report = inspect(build_session(config), config, target="Confidential web")
    consent = report["permissions"]["consent"]
    assert consent["admin_consent_complete"] is False
    assert [row["permission"] for row in consent["without_admin_consent"]] == [
        "Application.Read.All"
    ]
    assert "Application.Read.All" in consent["admin_consent_note"]
    assert "refused" in consent["admin_consent_note"]


@responses.activate
def test_inspecting_tells_a_personal_consent_from_a_tenant_one(
    config: Config,
) -> None:
    """One person consenting for themselves is not consent for the tenant."""
    register(
        grants=[
            {
                "clientId": "sp-1",
                "resourceId": GRAPH_APP,
                "consentType": "Principal",
                "principalId": "person-1",
                "scope": "User.Read",
            }
        ]
    )
    report = inspect(build_session(config), config, target="Confidential web")
    consent = report["permissions"]["consent"]
    assert consent["granted_delegated"] == ["User.Read"]
    assert consent["user_consented_only"][0]["principal_id"] == "person-1"
    assert "individual rather than for the tenant" in consent["admin_consent_note"]


@responses.activate
def test_inspecting_shows_the_groups_an_application_belongs_to(
    config: Config,
) -> None:
    """Access held through a group is recorded nowhere on the application."""
    register(
        member_of=[
            {
                "@odata.type": "#microsoft.graph.group",
                "id": "group-9",
                "displayName": "Log readers",
                "securityEnabled": True,
            },
            {
                "@odata.type": "#microsoft.graph.directoryRole",
                "id": "role-9",
                "displayName": "Global Reader",
            },
        ]
    )
    report = inspect(build_session(config), config, target="Confidential web")
    member_of = report["access"]["member_of"]
    assert member_of["security_groups"][0]["display_name"] == "Log readers"
    assert member_of["directory_roles"][0]["display_name"] == "Global Reader"


@responses.activate
def test_inspecting_something_that_is_not_there(config: Config) -> None:
    """A mistyped name says how to find the right one."""
    register()
    with pytest.raises(ApiCallError) as raised:
        inspect(build_session(config), config, target="no such application")
    assert "part of a display name" in raised.value.error.message


@responses.activate
def test_the_candidates_are_sorted_and_labelled(config: Config) -> None:
    """The chooser needs a stable order and a label with the identifier on it."""
    register()
    rows = candidates(build_session(config), config)
    labels = [label for _, label in rows]
    assert labels == sorted(labels, key=str.lower)
    assert any("(" in label for label in labels)


@responses.activate
def test_the_gallery_is_searched_by_prefix_then_narrowed(config: Config) -> None:
    """The endpoint filters on a prefix and is case sensitive, so this does the rest."""
    register(
        templates=[
            {"displayName": "Amazon Web Services", "publisher": "Amazon"},
            {"displayName": "Amazon SageMaker", "publisher": "Amazon"},
        ]
    )
    rows, note = search_gallery(build_session(config), config, "amazon web", 10)
    assert [row["displayName"] for row in rows] == ["Amazon Web Services"]
    assert note == ""


@responses.activate
def test_the_gallery_offers_near_matches(config: Config) -> None:
    """A prefix that matched is more use than an empty table."""
    register(templates=[{"displayName": "Amazon SageMaker", "publisher": "Amazon"}])
    rows, note = search_gallery(build_session(config), config, "amazon nothing", 10)
    assert rows
    assert "Nothing matched" in note


@responses.activate
def test_the_gallery_says_when_nothing_starts_with_the_term(config: Config) -> None:
    """An empty answer explains itself."""
    register(templates=[])
    rows, note = search_gallery(build_session(config), config, "zzzz", 10)
    assert rows == ()
    assert "Nothing in the gallery" in note


@responses.activate
def test_the_whole_gallery_can_be_listed(config: Config) -> None:
    """With no term it is a listing, not a search."""
    register(templates=[{"displayName": "Anything", "publisher": "Someone"}])
    rows, note = search_gallery(build_session(config), config, "", 10)
    assert len(rows) == 1
    assert note == ""


@responses.activate
def test_the_chooser_reads_names_not_whole_objects(config: Config) -> None:
    """A list of names must not cost a call for every object in the tenant.

    On a directory of several hundred, fetching owners and federated
    credentials for each one takes minutes and looks like a hang.
    """
    register()
    read_catalogue(build_session(config), config, lambda: "token")
    for call in responses.calls:
        url = call.request.url or ""
        assert "/owners" not in url, "the chooser fetched owners"
        assert "federatedIdentityCredentials" not in url
        assert "appRoleAssignedTo" not in url
    assert len(responses.calls) == 2


@responses.activate
def test_the_chooser_asks_for_only_the_fields_it_shows(config: Config) -> None:
    """Whole objects for a list of names is payload nobody reads."""
    register()
    read_catalogue(build_session(config), config)
    selected = [call.request.url or "" for call in responses.calls]
    assert all("select=" in url or "%24select=" in url for url in selected)


@responses.activate
def test_inspecting_one_application_is_a_handful_of_calls(config: Config) -> None:
    """Two to find it, then one each for the things that need their own call.

    The ceiling is a constant rather than a function of how large the tenant
    is, which is the property that matters: nothing here may become a call per
    object in the directory.
    """
    register()
    inspect(build_session(config), config, target="Confidential web")
    assert len(responses.calls) <= 12, [call.request.url for call in responses.calls]


@responses.activate
def test_inspecting_reads_no_object_twice(config: Config) -> None:
    """The application used to be fetched once to project and once again whole."""
    register()
    inspect(build_session(config), config, target="Confidential web")
    urls = [call.request.url or "" for call in responses.calls]
    assert len(urls) == len(set(urls)), sorted(urls)


@responses.activate
def test_managed_identities_are_kept_out_of_the_chooser(config: Config) -> None:
    """Azure creates one per resource, and Defender one per subscription."""
    register()
    catalogue = read_catalogue(build_session(config), config)
    types = {item.application_type for item in catalogue.principals}
    assert "managed-identity" not in types
    assert any("managed-identity" in note for note in catalogue.hidden)


@responses.activate
def test_asking_for_everything_includes_them(config: Config) -> None:
    """They are legitimate objects, just rarely the one being looked for."""
    register()
    catalogue = read_catalogue(build_session(config), config, everything=True)
    types = {item.application_type for item in catalogue.principals}
    assert "managed-identity" in types
    assert catalogue.hidden == ()


@responses.activate
def test_the_identifiers_line_up(config: Config) -> None:
    """A list where the identifier starts somewhere different on every line is
    a list nobody can read down."""
    register()
    rows = read_catalogue(build_session(config), config).lines()
    columns = {line.label.index(line.key) for line in rows if line.key in line.label}
    assert len(columns) == 1, f"identifiers start at {sorted(columns)}"


def test_a_name_too_long_for_the_column_is_shortened() -> None:
    """Rather than pushing every identifier off the screen."""
    from entrascope.inspect import NAME_WIDTH, shorten

    long_name = "aad-extensions-app. Do not modify. Used by AAD for storing user data."
    assert len(shorten(long_name, NAME_WIDTH)) == NAME_WIDTH
    assert shorten("short", NAME_WIDTH) == "short"
