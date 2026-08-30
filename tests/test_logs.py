"""Log interrogation tests, covering both the Graph route and the Monitor route."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote_plus

import pytest
import responses

from entrascope.config import Config
from entrascope.http import build_session
from entrascope.logs import (
    audit_events_from_rows,
    audit_filter,
    explain_missing_graph_route,
    graph_activity_from_rows,
    graph_route_available,
    initiator_name,
    query_audit_graph,
    query_audit_monitor,
    query_graph_activity,
    query_provisioning_graph,
    query_sign_ins_graph,
    query_sign_ins_monitor,
    sign_in_events_from_rows,
    sign_in_filter,
    sign_in_kinds,
    target_name,
)
from entrascope.models import ApiCallError, QueryResult
from tests.conftest import load_fixture

ROOT = "https://graph.microsoft.com/v1.0"


def asked_url(index: int = 0) -> str:
    """Return one recorded request URL with its query string decoded.

    A filter reaches Graph percent encoded, and asserting against the encoded
    form tests the encoding rather than the filter.
    """
    return unquote_plus(responses.calls[index].request.url or "")


# framework contract: azure-monitor-query defines the client and table shapes,
# so the doubles must present the same attributes.
class FakeTable:
    def __init__(self, columns: list[str], rows: list[list[Any]]) -> None:
        self.columns = columns
        self.rows = rows


# framework contract: the response shape is defined by azure-monitor-query.
class FakeResponse:
    def __init__(self, tables: list[FakeTable]) -> None:
        self.status = None
        self.tables = tables
        self.partial_data: list[FakeTable] = []
        self.partial_error = None


# framework contract: the client shape is defined by azure-monitor-query.
class FakeClient:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def query_workspace(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self.response


def test_audit_filter_uses_the_configured_category(config: Config) -> None:
    """Application management is the category that records registration changes."""
    assert audit_filter(config) == "category eq 'ApplicationManagement'"
    assert audit_filter(config, "directory-management").endswith("DirectoryManagement'")


def test_every_category_sends_no_category_clause(config: Config) -> None:
    """Asking for everything must not ask for a category called everything."""
    assert audit_filter(config, "all") == ""


def test_an_unknown_audit_category_lists_the_known_ones(config: Config) -> None:
    """A name that is not a category says which are, rather than reading nothing."""
    with pytest.raises(ApiCallError) as raised:
        audit_filter(config, "no-such-category")
    assert "application-management" in raised.value.error.message


def test_the_audit_filter_narrows_the_period_at_graph(config: Config) -> None:
    """A lookback applied after the rows arrive narrows nothing at all."""
    moment = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    built = audit_filter(config, lookback_hours=6, now=moment)
    assert "activityDateTime ge 2026-08-30T06:00:00Z" in built


def test_the_audit_filter_matches_an_object_id_at_graph(config: Config) -> None:
    """An object id can be matched at Graph; a display name cannot."""
    identifier = "11111111-1111-1111-1111-111111111111"
    assert f"t/id eq '{identifier}'" in audit_filter(config, target=identifier)
    assert "t/id eq" not in audit_filter(config, target="Confidential web")


@responses.activate
def test_audit_applicationmanagement(config: Config) -> None:
    """Audit events are read through Graph and projected."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/directoryAudits",
        json=load_fixture("audit_events"),
        status=200,
    )
    events = query_audit_graph(build_session(config), config)
    assert len(events) == 2
    assert events[0].activity == "Update application"
    assert events[0].category == "ApplicationManagement"
    assert events[0].target == "Confidential web application"
    assert "ApplicationManagement" in (responses.calls[0].request.url or "").replace(
        "%27", "'"
    )


@responses.activate
def test_audit_projects_both_initiator_shapes(config: Config) -> None:
    """An operation initiated by a user and one by an application both name someone."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/directoryAudits",
        json=load_fixture("audit_events"),
        status=200,
    )
    events = query_audit_graph(build_session(config), config)
    assert events[0].initiated_by.endswith("@example.invalid")
    assert events[1].initiated_by == "Confidential web application"


def test_initiator_and_target_tolerate_odd_shapes() -> None:
    """A payload that is not the expected shape yields an empty name, not an error."""
    assert initiator_name(None) == ""
    assert initiator_name({"user": {}}) == ""
    assert target_name(None) == ""
    assert target_name([{"nothing": True}]) == ""


def test_sign_in_kinds_are_configured(config: Config) -> None:
    """Four sign in kinds are queryable."""
    assert sign_in_kinds(config) == (
        "interactive",
        "managed-identity",
        "non-interactive",
        "service-principal",
    )


def test_sign_in_filter_distinguishes_the_kinds(config: Config) -> None:
    """Each kind filters on its own sign in event type, where the endpoint has one."""
    assert "servicePrincipal" in sign_in_filter(config, "service-principal")
    assert "managedIdentity" in sign_in_filter(config, "managed-identity")
    # The version 1.0 endpoint has no signInEventTypes property and returns
    # interactive sign ins already, so that kind sends no event type clause.
    assert sign_in_filter(config, "interactive") == ""
    assert sign_in_filter(config, "interactive", "aaaa") == "appId eq 'aaaa'"


def test_only_the_beta_endpoint_carries_the_event_type(config: Config) -> None:
    """The kinds that filter on signInEventTypes are routed to the beta endpoint."""
    from entrascope.logs import sign_in_entry

    assert not sign_in_entry(config, "interactive").graph_beta
    for kind in ("non-interactive", "service-principal", "managed-identity"):
        assert sign_in_entry(config, kind).graph_beta


def test_an_unknown_sign_in_kind_lists_the_known_ones(config: Config) -> None:
    """Asking for a kind that does not exist says which do."""
    with pytest.raises(ApiCallError) as raised:
        sign_in_filter(config, "telepathy")
    assert "interactive" in raised.value.error.message


@responses.activate
def test_signin_query_graph(config: Config) -> None:
    """Sign ins are read through Graph and projected."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/signIns",
        json=load_fixture("sign_ins"),
        status=200,
    )
    events = query_sign_ins_graph(build_session(config), config)
    assert len(events) == 2
    assert events[1].error_code == 50011
    assert events[1].failed()
    assert not events[0].failed()


@responses.activate
def test_signin_query_asks_graph_for_the_failures(config: Config) -> None:
    """Keeping the failures out of the newest rows answers a different question.

    Asking for the newest twenty five sign ins and then discarding the
    successes reports whether any of those twenty five failed, which is not
    what somebody diagnosing a failure asked. The clause goes to Graph.
    """
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/signIns",
        json=load_fixture("sign_ins"),
        status=200,
    )
    query_sign_ins_graph(build_session(config), config, failures_only=True)
    assert "status/errorCode ne 0" in asked_url()


@responses.activate
def test_signin_query_narrows_at_graph_rather_than_afterwards(
    config: Config,
) -> None:
    """The application, the period and the order all go to the service."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/signIns",
        json=load_fixture("sign_ins"),
        status=200,
    )
    query_sign_ins_graph(
        build_session(config),
        config,
        app_id="aaaaaaaa-1111-1111-1111-111111111111",
        lookback_hours=6,
    )
    asked = asked_url()
    assert "appId eq 'aaaaaaaa-1111-1111-1111-111111111111'" in asked
    assert "createdDateTime ge" in asked


def test_sign_ins_ask_for_no_order_by_default(config: Config) -> None:
    """The endpoint already answers newest first, and asking can be refused.

    Microsoft Graph rejects $orderby combined with a $filter on a different
    property on several reporting collections, so asking for an order the
    endpoint already gives would trade a correct answer for a refusal. The
    setting is configuration, so a tenant that wants it stated can say so.
    """
    assert config.tables.sign_in_filters.graph_order_by == ""


@responses.activate
def test_provisioning_is_returned_unprojected(config: Config) -> None:
    """Provisioning payloads vary by connector, so they are returned as they arrive."""
    responses.add(
        responses.GET,
        f"{ROOT}/auditLogs/provisioning",
        json={"value": [{"id": "prov-1", "anything": {"nested": True}}]},
        status=200,
    )
    rows = query_provisioning_graph(build_session(config), config)
    assert rows[0]["anything"]["nested"] is True


def test_signin_query_kql(config: Config) -> None:
    """The Monitor route returns the same objects as the Graph route."""
    table = FakeTable(
        [
            "TimeGenerated",
            "UserPrincipalName",
            "AppId",
            "AppDisplayName",
            "ResultType",
            "ResultDescription",
            "CorrelationId",
        ],
        [
            [
                "2026-08-22T08:20:00Z",
                "engineer@example.invalid",
                "aaaaaaaa-1111-1111-1111-111111111111",
                "Confidential web application",
                50011,
                "Redirect URI mismatch",
                "dddddddd-bbbb-1111-1111-111111111111",
            ]
        ],
    )
    client = FakeClient(FakeResponse([table]))
    events = query_sign_ins_monitor(client, config, "workspace", kind="interactive")
    assert events[0].error_code == 50011
    assert events[0].identity == "engineer@example.invalid"
    assert events[0].failed()


def test_monitor_sign_in_query_rejects_an_unknown_kind(config: Config) -> None:
    """The Monitor route validates the kind the same way the Graph route does."""
    client = FakeClient(FakeResponse([]))
    with pytest.raises(ApiCallError):
        query_sign_ins_monitor(client, config, "workspace", kind="telepathy")


def test_audit_query_through_monitor(config: Config) -> None:
    """Audit events read through Monitor project into the same objects."""
    table = FakeTable(
        ["TimeGenerated", "OperationName", "Category", "Result", "TargetName"],
        [
            [
                "2026-08-21T14:02:11Z",
                "Update application",
                "ApplicationManagement",
                "success",
                "App",
            ]
        ],
    )
    events = query_audit_monitor(FakeClient(FakeResponse([table])), config, "workspace")
    assert events[0].activity == "Update application"
    assert events[0].target == "App"


def test_graph_activity_query(config: Config) -> None:
    """Microsoft Graph activity projects its own object."""
    table = FakeTable(
        [
            "TimeGenerated",
            "AppId",
            "RequestMethod",
            "ResponseStatusCode",
            "RequestUri",
            "DurationMs",
        ],
        [["2026-08-22T09:00:00Z", "aaaa", "GET", 403, "/v1.0/applications", 42]],
    )
    client = FakeClient(FakeResponse([table]))
    events = query_graph_activity(client, config, "workspace")
    assert events[0].status == 403
    assert events[0].duration_ms == 42


def test_graph_activity_has_no_graph_route(config: Config) -> None:
    """Graph activity exists only through Azure Monitor, and the message says so."""
    assert not graph_route_available(config, "graph-activity")
    assert graph_route_available(config, "audit")
    message = explain_missing_graph_route(config, "graph-activity")
    assert "MicrosoftGraphActivityLogs" in message


def test_projection_from_rows_tolerates_missing_columns() -> None:
    """A query that selected fewer columns still projects."""
    empty = QueryResult(columns=("TimeGenerated",), rows=(("now",),))
    assert audit_events_from_rows(empty)[0].timestamp == "now"
    assert sign_in_events_from_rows(empty)[0].error_code == 0
    assert graph_activity_from_rows(empty)[0].status == 0


def test_a_row_limit_is_brought_inside_its_ceiling(config: Config) -> None:
    """Ten million rows is a way to hang a terminal, not a way to read a log."""
    from entrascope.logs import query_parameters

    parameters = query_parameters(config, row_limit=10_000_000)
    assert parameters["row_limit"] == config.tables.defaults.max_row_limit


def test_a_nonsense_lookback_becomes_a_number_of_something(config: Config) -> None:
    """A negative lookback is not a question a workspace can answer."""
    from entrascope.logs import query_parameters

    assert query_parameters(config, lookback_hours=-5)["lookback_hours"] == 1
