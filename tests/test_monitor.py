"""Azure Monitor log query tests."""

from __future__ import annotations

from typing import Any

import pytest
from azure.core.exceptions import HttpResponseError
from azure.monitor.query import LogsQueryStatus

from entrascope.config import Config, load_config
from entrascope.models import ApiCallError, QueryResult
from entrascope.monitor import (
    build_query,
    query_workspace,
    run_template,
    table_for,
    to_query_result,
)


@pytest.fixture
def config() -> Config:
    """Return the repository configuration."""
    return load_config()


# framework contract: azure-monitor-query returns table and response objects, so
# the doubles must present the same attributes.
class FakeTable:
    def __init__(self, columns: list[str], rows: list[list[Any]]) -> None:
        self.columns = columns
        self.rows = rows


# framework contract: the response shape is defined by azure-monitor-query.
class FakeResponse:
    def __init__(
        self,
        status: Any = LogsQueryStatus.SUCCESS,
        tables: list[FakeTable] | None = None,
        partial_data: list[FakeTable] | None = None,
        partial_error: str | None = None,
    ) -> None:
        self.status = status
        self.tables = tables or []
        self.partial_data = partial_data or []
        self.partial_error = partial_error


# framework contract: the client shape is defined by azure-monitor-query.
class FakeClient:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def query_workspace(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def test_table_for_maps_a_category(config: Config) -> None:
    """Every diagnostic category maps to its Log Analytics table."""
    assert table_for(config, "SignInLogs") == "SigninLogs"
    assert table_for(config, "AuditLogs") == "AuditLogs"


def test_unknown_category_lists_the_configured_ones(config: Config) -> None:
    """An unknown category names the ones that are configured."""
    with pytest.raises(ApiCallError) as raised:
        table_for(config, "NoSuchCategory")
    assert "SignInLogs" in raised.value.error.message


def test_build_query_renders_a_template(config: Config) -> None:
    """A template is rendered with its parameters and never concatenated."""
    query = build_query(
        config,
        "signins_failures",
        {"lookback_hours": 6, "app_filter": "abc", "row_limit": 10},
    )
    assert "let lookback = 6h;" in query
    assert 'AppId == "abc"' in query
    assert "take 10" in query


def test_logs_query_returns_rows(config: Config) -> None:
    """A successful query yields columns and rows as an immutable result."""
    table = FakeTable(["TimeGenerated", "ResultType"], [["now", 50011], ["then", 0]])
    client = FakeClient(FakeResponse(tables=[table]))
    result = query_workspace(client, "workspace", "AuditLogs | take 1", 24)
    assert result.columns == ("TimeGenerated", "ResultType")
    assert len(result.rows) == 2
    assert not result.partial
    assert result.as_dicts()[0]["ResultType"] == 50011


def test_partial_results_are_kept_with_their_reason(config: Config) -> None:
    """A partial result returns the rows it did produce, and says why."""
    table = FakeTable(["A"], [["one"]])
    response = FakeResponse(
        status=LogsQueryStatus.PARTIAL, partial_data=[table], partial_error="timed out"
    )
    result = query_workspace(FakeClient(response), "workspace", "query", 1)
    assert result.partial
    assert result.rows == (("one",),)
    assert "timed out" in result.detail


def test_a_failed_query_raises_the_structured_error() -> None:
    """A failure carries its reason in the one error type."""
    response = FakeResponse(status=LogsQueryStatus.FAILURE, partial_error="bad syntax")
    with pytest.raises(ApiCallError) as raised:
        query_workspace(FakeClient(response), "workspace", "query", 1)
    assert "bad syntax" in raised.value.error.message


def test_an_empty_result_is_not_an_error() -> None:
    """A query that matched nothing returns an empty result."""
    result = to_query_result(FakeResponse(tables=[]))
    assert result == QueryResult(columns=(), rows=(), partial=False, detail="No data.")


def test_a_transport_failure_becomes_the_structured_error() -> None:
    """An HTTP failure from the client is reported like every other API error."""
    error = HttpResponseError(message="Forbidden")
    error.status_code = 403
    with pytest.raises(ApiCallError) as raised:
        query_workspace(FakeClient(error), "workspace", "query", 1)
    assert raised.value.error.status == 403
    assert raised.value.error.source == "azure-monitor"


def test_run_template_passes_the_lookback(config: Config) -> None:
    """The timespan follows the lookback the template was rendered with."""
    client = FakeClient(FakeResponse(tables=[FakeTable(["A"], [])]))
    run_template(
        client,
        config,
        "workspace",
        "audit_applicationmanagement",
        {"lookback_hours": 48, "target_filter": "", "row_limit": 5},
    )
    assert client.calls[0]["timespan"].total_seconds() == 48 * 3600
