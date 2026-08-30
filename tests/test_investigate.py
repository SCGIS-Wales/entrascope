"""Investigation tests: from a symptom to a ranked set of findings."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import responses

from entrascope.config import Config
from entrascope.discovery import (
    is_first_party,
    project_application,
    project_service_principal,
)
from entrascope.http import build_session
from entrascope.investigate import (
    TENANT_TARGET,
    audit_findings,
    collapse_sign_in_failures,
    configuration_findings,
    credential_findings,
    filter_by_severity,
    investigate,
    is_insecure,
    matches,
    rank,
    sign_in_findings,
    times,
)
from entrascope.models import AuditEvent, Finding, SignInEvent
from tests.conftest import load_fixture

ROOT = "https://graph.microsoft.com/v1.0"
NOW = datetime(2026, 8, 22, tzinfo=UTC)


def finding(severity: str, area: str = "a", occurrences: int = 1) -> Finding:
    """Build a finding for the ordering tests."""
    return Finding(
        severity=severity,  # type: ignore[arg-type]
        area=area,
        subject="s",
        detail="d",
        occurrences=occurrences,
    )


def test_times_reads_like_a_person_wrote_it() -> None:
    """One failure is once, and more than one is a count."""
    assert times(1) == "once"
    assert times(4) == "4 times"


def test_an_application_matches_by_any_identifier(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """An engineer has whichever identifier the error message gave them."""
    summary = project_application(applications[0], config, now=NOW)
    assert matches(summary, summary.app_id)
    assert matches(summary, summary.object_id)
    assert matches(summary, "confidential web")
    assert not matches(summary, "something else entirely")


def test_expired_credentials_are_errors_and_expiring_ones_warnings(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """An expired secret has already broken something. An expiring one will."""
    summary = project_application(applications[0], config, now=NOW)
    findings = credential_findings(summary, config)
    assert {item.severity for item in findings} == {"error"}
    assert findings[0].code == "AADSTS7000222"
    assert findings[0].remediation

    expiring = project_application(applications[4], config, now=NOW)
    warnings = credential_findings(expiring, config)
    assert warnings[0].severity == "warning"
    assert "warning window" in warnings[0].detail


def test_an_application_with_no_owner_is_flagged(
    config: Config, applications: list[dict[str, Any]]
) -> None:
    """Nobody is named as responsible for it."""
    summary = project_application(applications[1], config, now=NOW)
    areas = {item.area for item in configuration_findings(summary, config)}
    assert "ownership" in areas


def test_an_insecure_redirect_is_flagged_but_localhost_is_not(
    config: Config,
) -> None:
    """Plain HTTP to a remote host leaks an authorisation code. Localhost does not."""
    assert is_insecure("http://app.example.invalid/callback", config)
    assert not is_insecure("http://localhost:8400", config)
    assert not is_insecure("http://127.0.0.1:8400", config)
    assert not is_insecure("https://app.example.invalid/callback", config)


def test_a_disabled_enterprise_application_is_an_error(
    config: Config, service_principals: list[dict[str, Any]]
) -> None:
    """Every sign in fails whatever else is configured."""
    from entrascope.investigate import principal_findings

    legacy = next(
        row for row in service_principals if row["displayName"] == "Legacy application"
    )
    summary = project_service_principal(legacy, config, now=NOW)
    findings = principal_findings(summary, config)
    assert findings[0].severity == "error"
    assert "disabled" in findings[0].detail


def test_assignment_required_is_a_note_not_a_failure(
    config: Config, service_principals: list[dict[str, Any]]
) -> None:
    """It explains a refusal rather than being one."""
    from entrascope.investigate import principal_findings

    confidential = project_service_principal(service_principals[0], config, now=NOW)
    findings = principal_findings(confidential, config)
    assert [item.severity for item in findings] == ["note"]


def test_failed_directory_operations_are_grouped(config: Config) -> None:
    """Twenty failures of one operation are one finding, not twenty."""
    events = tuple(
        AuditEvent(
            id=str(index),
            activity="Update application",
            category="ApplicationManagement",
            result="failure",
            reason="Authorization_RequestDenied",
            timestamp="2026-08-21T14:02:11Z",
            initiated_by="someone@example.invalid",
            target="my-api",
        )
        for index in range(20)
    )
    findings = audit_findings(events, config)
    assert len(findings) == 1
    assert findings[0].occurrences == 20
    assert findings[0].severity == "error"
    assert "permission" in findings[0].remediation.lower()


def test_a_successful_operation_is_not_a_finding(config: Config) -> None:
    """Only failures are worth an engineer's attention."""
    events = (
        AuditEvent(
            id="1",
            activity="Update application",
            category="ApplicationManagement",
            result="success",
            reason="",
            timestamp="2026-08-21T14:02:11Z",
            initiated_by="someone@example.invalid",
            target="my-api",
        ),
    )
    assert audit_findings(events, config) == ()


def test_failed_sign_ins_are_grouped_and_explained(config: Config) -> None:
    """Each error code becomes one finding carrying its remediation."""
    events = tuple(
        SignInEvent(
            id=str(index),
            timestamp="2026-08-22T08:20:00Z",
            identity="engineer@example.invalid",
            app_id="aaaa",
            app_display_name="my-api",
            resource="Microsoft Graph",
            client_app="Browser",
            ip_address="203.0.113.11",
            error_code=50011,
            failure_reason="redirect mismatch",
        )
        for index in range(3)
    )
    findings = sign_in_findings(events, config)
    assert len(findings) == 1
    assert findings[0].code == "AADSTS50011"
    assert findings[0].occurrences == 3
    assert "byte for byte" in findings[0].remediation


def test_a_successful_sign_in_is_not_a_finding(config: Config) -> None:
    """Only failures are reported."""
    event = SignInEvent(
        id="1",
        timestamp="2026-08-22T08:15:00Z",
        identity="engineer@example.invalid",
        app_id="aaaa",
        app_display_name="my-api",
        resource="Microsoft Graph",
        client_app="Browser",
        ip_address="203.0.113.10",
        error_code=0,
        failure_reason="Other.",
    )
    assert sign_in_findings((event,), config) == ()


def test_findings_are_ranked_worst_first() -> None:
    """Errors first, then by how often each was seen."""
    ordered = rank(
        [
            finding("note"),
            finding("warning"),
            finding("error", occurrences=1),
            finding("error", occurrences=9),
        ]
    )
    assert [item.severity for item in ordered] == ["error", "error", "warning", "note"]
    assert ordered[0].occurrences == 9


def test_severity_filtering() -> None:
    """A severity shows that level and worse, so errors alone can be asked for."""
    everything = [finding("error"), finding("warning"), finding("note")]
    assert len(filter_by_severity(everything, "error")) == 1
    assert len(filter_by_severity(everything, "warning")) == 2
    assert len(filter_by_severity(everything, "note")) == 3
    assert len(filter_by_severity(everything, None)) == 3


def test_repeated_refusals_collapse_into_one_note() -> None:
    """Four kinds refused for one reason is one note, not four."""
    collapsed = collapse_sign_in_failures(
        [
            ("interactive", "no premium licence"),
            ("non-interactive", "no premium licence"),
            ("service-principal", "no premium licence"),
            ("managed-identity", "something else"),
        ]
    )
    assert len(collapsed) == 2
    assert any(
        "interactive, non-interactive, service-principal" in note for note in collapsed
    )


def test_first_party_applications_are_recognised(
    config: Config, service_principals: list[dict[str, Any]]
) -> None:
    """Microsoft owns hundreds of them and they are not the engineer's problem."""
    payload = dict(service_principals[0])
    payload["appOwnerOrganizationId"] = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
    assert is_first_party(project_service_principal(payload, config, now=NOW), config)
    assert not is_first_party(
        project_service_principal(service_principals[0], config, now=NOW), config
    )


def register_graph(
    *,
    audit: bool = True,
    details: bool = True,
    grants: list[dict[str, Any]] | None = None,
    resources: dict[str, Any] | None = None,
) -> None:
    """Register the Graph responses an investigation makes.

    Discovery fetches owners, federated credentials and role assignments one
    object at a time when a token is supplied, so those are matched by pattern.
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
    if audit:
        responses.add(
            responses.GET,
            f"{ROOT}/auditLogs/directoryAudits",
            json=load_fixture("audit_events"),
            status=200,
        )
    else:
        responses.add(
            responses.GET,
            f"{ROOT}/auditLogs/directoryAudits",
            json={"error": {"code": "Authorization_RequestDenied", "message": "no"}},
            status=403,
        )
    responses.add(
        responses.GET,
        f"{ROOT}/oauth2PermissionGrants",
        json={"value": grants or []},
        status=200,
    )
    responses.add(
        responses.GET,
        re.compile(rf"{re.escape(ROOT)}/servicePrincipals\(appId="),
        json=resources
        if resources is not None
        else {
            "displayName": "Microsoft Graph",
            "oauth2PermissionScopes": [
                {
                    "id": "eeee1111-1111-1111-1111-111111111111",
                    "value": "User.Read",
                    "type": "User",
                }
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
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/signIns",
        json=load_fixture("sign_ins"),
        status=200,
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/beta/auditLogs/signIns",
        json={"value": []},
        status=200,
    )
    if details:
        responses.add(
            responses.GET,
            re.compile(rf"{re.escape(ROOT)}/applications/[^/]+/owners"),
            json=load_fixture("owners"),
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(
                rf"{re.escape(ROOT)}/applications/[^/]+/federatedIdentityCredentials"
            ),
            json={"value": []},
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(rf"{re.escape(ROOT)}/servicePrincipals/[^/]+/owners"),
            json={"value": []},
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(rf"{re.escape(ROOT)}/servicePrincipals/[^/]+/appRoleAssignedTo"),
            json={"value": []},
            status=200,
        )


@responses.activate
def test_a_permission_never_admin_consented_becomes_an_error(
    config: Config,
) -> None:
    """The commonest cause of a permission failure should be the loudest finding."""
    register_graph()
    result = investigate(build_session(config), config, limit=10)
    consent = [item for item in result.findings if item.area == "consent"]
    assert consent, [item.area for item in result.findings]
    assert consent[0].severity == "error"
    assert "Application.Read.All" in consent[0].detail
    assert "admin-consent" in consent[0].remediation


@responses.activate
def test_a_personal_consent_is_reported_separately(config: Config) -> None:
    """It works for one person, so it is a warning rather than a plain refusal."""
    register_graph(
        grants=[
            {
                "clientId": "66666666-6666-6666-6666-666666666666",
                "resourceId": "00000003-0000-0000-c000-000000000000",
                "consentType": "Principal",
                "principalId": "person-1",
                "scope": "User.Read",
            }
        ]
    )
    result = investigate(build_session(config), config, limit=10)
    personal = [
        item
        for item in result.findings
        if item.area == "consent" and item.severity == "warning"
    ]
    assert personal
    assert "User.Read" in personal[0].detail


@responses.activate
def test_a_tenant_wide_investigation(config: Config) -> None:
    """With no target the whole tenant is swept."""
    register_graph()
    result = investigate(build_session(config), config, limit=10)
    assert result.scope == "tenant"
    assert result.target == TENANT_TARGET
    assert result.findings
    assert result.errors()
    assert any(item.area == "sign in" for item in result.findings)
    assert any(item.area == "directory operation" for item in result.findings)


@responses.activate
def test_an_investigation_narrows_to_one_application(config: Config) -> None:
    """A target narrows the applications, the audits and the sign ins."""
    register_graph()
    result = investigate(
        build_session(config), config, target="Confidential web application", limit=10
    )
    assert result.scope == "application"
    assert [item.display_name for item in result.applications] == [
        "Confidential web application"
    ]
    assert all("Single page" not in item.subject for item in result.findings)


@responses.activate
def test_an_unavailable_source_becomes_a_note_not_an_empty_report(
    config: Config,
) -> None:
    """One refusal must not empty a report the rest of which is fine."""
    register_graph(audit=False)
    result = investigate(build_session(config), config, limit=10)
    assert any("Audit logs unavailable" in note for note in result.notes)
    assert result.findings


@responses.activate
def test_severity_filtering_reaches_the_investigation(config: Config) -> None:
    """Asking for errors returns only what is already broken."""
    register_graph()
    result = investigate(
        build_session(config), config, limit=10, minimum_severity="error"
    )
    assert {item.severity for item in result.findings} == {"error"}


@responses.activate
def test_a_target_that_matches_nothing_is_not_an_error(config: Config) -> None:
    """An engineer mistyping a name gets an empty report, not a failure."""
    register_graph()
    result = investigate(build_session(config), config, target="no-such-app", limit=10)
    assert result.applications == ()
    assert result.findings == ()


@responses.activate
def test_a_truncated_investigation_says_so(config: Config) -> None:
    """A large tenant holds more objects than an investigation should walk."""
    register_graph()
    tight = config.model_copy(
        update={
            "retry": config.retry.model_copy(
                update={
                    "paging": config.retry.paging.model_copy(update={"max_objects": 2})
                }
            )
        }
    )
    result = investigate(build_session(tight), tight, limit=5)
    assert len(result.applications) == 2
    assert any("reached the ceiling" in note for note in result.notes)


@responses.activate
def test_an_untruncated_investigation_says_nothing_about_it(config: Config) -> None:
    """A note that is always there is a note nobody reads."""
    register_graph()
    result = investigate(build_session(config), config, limit=5)
    assert not any("ceiling" in note for note in result.notes)
