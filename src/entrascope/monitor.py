"""Azure Monitor log queries.

A thin functional wrapper over the Log Analytics client. Query text always comes
from a KQL template in ``config/kql/`` rendered with named parameters, never
from concatenation.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

from entrascope.config import Config, load_kql, render_kql
from entrascope.logger import get_logger
from entrascope.models import ApiCallError, ApiError, QueryResult

log = get_logger(__name__)

#: Source name used on errors raised from this module.
SOURCE = "azure-monitor"


def build_logs_client(credential: TokenCredential) -> LogsQueryClient:
    """Build the Log Analytics query client."""
    # framework contract: azure-monitor-query exposes a client object. It is
    # treated as configuration and carries none of our logic.
    return LogsQueryClient(credential)


def table_for(config: Config, category: str) -> str:
    """Return the Log Analytics table that one diagnostic category populates."""
    for entry in config.tables.diagnostic_categories:
        if entry.name == category:
            return entry.table
    known = sorted(entry.name for entry in config.tables.diagnostic_categories)
    raise ApiCallError(
        ApiError(
            status=0,
            code="UnknownCategory",
            message=f"No diagnostic category named {category}. Configured: {known}.",
            source="config",
        )
    )


def build_query(config: Config, template_name: str, parameters: dict[str, Any]) -> str:
    """Render one KQL template with its parameters."""
    return render_kql(load_kql(template_name, config), parameters)


def to_query_result(response: Any) -> QueryResult:
    """Convert a client response into the immutable result every surface renders.

    A partial result carries the rows it did return along with the reason, which
    is more useful than discarding them.
    """
    if getattr(response, "status", None) == LogsQueryStatus.FAILURE:
        error = getattr(response, "partial_error", None)
        raise ApiCallError(
            ApiError(
                status=0,
                code="QueryFailure",
                message=str(error) if error else "The log query failed.",
                source=SOURCE,
            )
        )
    partial = getattr(response, "status", None) == LogsQueryStatus.PARTIAL
    tables = getattr(response, "partial_data", None) if partial else response.tables
    if not tables:
        return QueryResult(columns=(), rows=(), partial=partial, detail="No data.")
    table = tables[0]
    return QueryResult(
        columns=tuple(str(name) for name in table.columns),
        rows=tuple(tuple(row) for row in table.rows),
        partial=partial,
        detail=str(getattr(response, "partial_error", "")) if partial else "",
    )


def query_workspace(
    client: LogsQueryClient,
    workspace_id: str,
    query: str,
    lookback_hours: int,
) -> QueryResult:
    """Run one KQL query against a Log Analytics workspace."""
    try:
        response = client.query_workspace(
            workspace_id=workspace_id,
            query=query,
            timespan=timedelta(hours=lookback_hours),
        )
    except HttpResponseError as error:
        raise ApiCallError(
            ApiError(
                status=int(error.status_code or 0),
                code=str(getattr(error, "error", None) or "QueryError"),
                message=str(error.message),
                source=SOURCE,
            )
        ) from error
    result = to_query_result(response)
    log.debug(
        "log query returned %s rows",
        len(result.rows),
        extra={"api": SOURCE, "partial": result.partial},
    )
    return result


def run_template(
    client: LogsQueryClient,
    config: Config,
    workspace_id: str,
    template_name: str,
    parameters: dict[str, Any],
) -> QueryResult:
    """Render a KQL template and run it, in one call."""
    lookback = int(parameters.get("lookback_hours", 24))
    return query_workspace(
        client, workspace_id, build_query(config, template_name, parameters), lookback
    )
