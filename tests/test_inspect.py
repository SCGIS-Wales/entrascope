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
    search_gallery,
    urls,
)
from entrascope.models import ApiCallError
from tests.conftest import load_fixture

ROOT = "https://graph.microsoft.com/v1.0"
GRAPH_APP = "00000003-0000-0000-c000-000000000000"


def register(*, templates: list[dict[str, Any]] | None = None) -> None:
    """Register the calls an inspection makes.

    Discovery fetches owners and federated credentials one object at a time
    when a token is supplied, which the command line does, so those are matched
    by pattern.
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
            {"value": []},
        ),
    ):
        responses.add(responses.GET, re.compile(pattern), json=body, status=200)
    responses.add(
        responses.GET,
        re.compile(rf"{re.escape(ROOT)}/applications/[0-9a-f-]+"),
        json=load_fixture("applications")["value"][0],
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
    assert "never recorded" in state["admin_consent_note"]


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
            ),
        )
    )
    assert consent_state(None, principal)["admin_consent_granted"] is True


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
