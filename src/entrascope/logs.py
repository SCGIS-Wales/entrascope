"""Log interrogation.

Seven sources, reachable two ways. The Graph reporting API works on any tenant
with the right permission. The Azure Monitor route needs a diagnostic setting,
a workspace and the Log Analytics Reader role, and gives longer retention.

Both routes return the same data transfer objects, so a caller never needs to
know which one answered.

Entra directory operations do not appear in the Azure subscription activity log.
They are recorded in the Entra audit logs, which is what this module reads.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from azure.monitor.query import LogsQueryClient

from entrascope.config import Config, SignInKind
from entrascope.discovery import pluck, text
from entrascope.graph import get_collection
from entrascope.http import Session
from entrascope.logger import get_logger
from entrascope.models import (
    ApiCallError,
    ApiError,
    AuditEvent,
    GraphActivityEvent,
    QueryResult,
    SignInEvent,
)
from entrascope.monitor import run_template

log = get_logger(__name__)

#: Rendered into the message when a source has no Graph route.
GRAPH_UNSUPPORTED = (
    "{name} is not available through Microsoft Graph. Query it through Azure "
    "Monitor with a workspace, which needs the {category} diagnostic category."
)


def sign_in_kinds(config: Config) -> tuple[str, ...]:
    """Return the sign in kinds that can be queried."""
    return tuple(sorted(config.tables.sign_in_kinds))


def initiator_name(payload: Any) -> str:
    """Return who performed an audited operation, whoever they were.

    Graph reports the initiator as a user, an application or both, so all three
    shapes are handled.
    """
    if not isinstance(payload, Mapping):
        return text(payload)
    for key in ("user", "app"):
        actor = payload.get(key)
        if isinstance(actor, Mapping):
            name = (
                actor.get("userPrincipalName")
                or actor.get("displayName")
                or actor.get("servicePrincipalName")
                or actor.get("id")
            )
            if name:
                return text(name)
    return ""


def target_name(payload: Any) -> str:
    """Return the display name of the first target of an audited operation."""
    if isinstance(payload, Sequence) and not isinstance(payload, str):
        for item in payload:
            if isinstance(item, Mapping):
                name = item.get("displayName") or item.get("id")
                if name:
                    return text(name)
    return ""


def project_audit_event(payload: Mapping[str, Any], config: Config) -> AuditEvent:
    """Project one directory audit event from a Graph payload."""
    mapping = config.fields.audit
    return AuditEvent(
        id=text(pluck(payload, mapping["id"])),
        activity=text(pluck(payload, mapping["activity"])),
        category=text(pluck(payload, mapping["category"])),
        result=text(pluck(payload, mapping["result"])),
        reason=text(pluck(payload, mapping["reason"])),
        timestamp=text(pluck(payload, mapping["activity_date_time"])),
        initiated_by=initiator_name(pluck(payload, mapping["initiated_by"])),
        target=target_name(pluck(payload, mapping["target_resources"])),
        correlation_id=text(payload.get("correlationId")),
    )


def project_sign_in_event(payload: Mapping[str, Any], config: Config) -> SignInEvent:
    """Project one sign in from a Graph payload."""
    mapping = config.fields.sign_in
    error_code = pluck(payload, mapping["error_code"])
    return SignInEvent(
        id=text(pluck(payload, mapping["id"])),
        timestamp=text(pluck(payload, mapping["created"])),
        identity=text(pluck(payload, mapping["user_principal_name"])),
        app_id=text(pluck(payload, mapping["app_id"])),
        app_display_name=text(pluck(payload, mapping["app_display_name"])),
        resource=text(pluck(payload, mapping["resource_display_name"])),
        client_app=text(pluck(payload, mapping["client_app_used"])),
        ip_address=text(pluck(payload, mapping["ip_address"])),
        error_code=int(error_code) if isinstance(error_code, int) else 0,
        failure_reason=text(pluck(payload, mapping["failure_reason"])),
        correlation_id=text(payload.get("correlationId")),
    )


def row_value(row: Mapping[str, Any], *names: str) -> Any:
    """Return the first present column out of several candidate names.

    Log Analytics and Graph name the same field differently, so a projection
    from a KQL row accepts either spelling.
    """
    for name in names:
        if name in row and row[name] is not None:
            return row[name]
    return None


def audit_events_from_rows(result: QueryResult) -> tuple[AuditEvent, ...]:
    """Project audit events from a Log Analytics result."""
    return tuple(
        AuditEvent(
            id=text(row_value(row, "Id", "CorrelationId")),
            activity=text(row_value(row, "OperationName", "ActivityDisplayName")),
            category=text(row_value(row, "Category")),
            result=text(row_value(row, "Result")),
            reason=text(row_value(row, "ResultReason")),
            timestamp=text(row_value(row, "TimeGenerated")),
            initiated_by=initiator_name(row_value(row, "InitiatedBy")),
            target=text(row_value(row, "TargetName", "TargetResources")),
            correlation_id=text(row_value(row, "CorrelationId")),
        )
        for row in result.as_dicts()
    )


def sign_in_events_from_rows(result: QueryResult) -> tuple[SignInEvent, ...]:
    """Project sign ins from a Log Analytics result."""
    return tuple(
        SignInEvent(
            id=text(row_value(row, "Id", "CorrelationId")),
            timestamp=text(row_value(row, "TimeGenerated")),
            identity=text(row_value(row, "UserPrincipalName", "Identity")),
            app_id=text(row_value(row, "AppId")),
            app_display_name=text(row_value(row, "AppDisplayName")),
            resource=text(row_value(row, "ResourceDisplayName")),
            client_app=text(row_value(row, "ClientAppUsed")),
            ip_address=text(row_value(row, "IPAddress")),
            error_code=int(row_value(row, "ResultType") or 0),
            failure_reason=text(row_value(row, "ResultDescription")),
            correlation_id=text(row_value(row, "CorrelationId")),
        )
        for row in result.as_dicts()
    )


def graph_activity_from_rows(result: QueryResult) -> tuple[GraphActivityEvent, ...]:
    """Project Microsoft Graph activity from a Log Analytics result."""
    return tuple(
        GraphActivityEvent(
            timestamp=text(row_value(row, "TimeGenerated")),
            app_id=text(row_value(row, "AppId")),
            service_principal_id=text(row_value(row, "ServicePrincipalId")),
            user_id=text(row_value(row, "UserId")),
            method=text(row_value(row, "RequestMethod")),
            status=int(row_value(row, "ResponseStatusCode") or 0),
            uri=text(row_value(row, "RequestUri")),
            roles=text(row_value(row, "Roles")),
            scopes=text(row_value(row, "Scopes")),
            duration_ms=int(row_value(row, "DurationMs") or 0),
            request_id=text(row_value(row, "RequestId")),
        )
        for row in result.as_dicts()
    )


def audit_filter(config: Config, category: str | None = None) -> str:
    """Return the OData filter that limits audits to one category."""
    query = config.tables.log_queries["audit"]
    wanted = category or config.tables.audit_categories["application_management"]
    return query.graph_filter_template.format(category=wanted)


def query_audit_graph(
    session: Session,
    config: Config,
    *,
    category: str | None = None,
    top: int | None = None,
) -> tuple[AuditEvent, ...]:
    """Read directory audit events through Microsoft Graph."""
    payloads = get_collection(
        session,
        config,
        "directory_audits",
        filter_expression=audit_filter(config, category),
        limit=top or config.tables.defaults.row_limit,
        order_by="activityDateTime desc",
    )
    log.info("read %s audit events through Graph", len(payloads))
    return tuple(project_audit_event(payload, config) for payload in payloads)


def sign_in_entry(config: Config, kind: str) -> SignInKind:
    """Return the configuration for one sign in kind, or explain what exists."""
    entry = config.tables.sign_in_kinds.get(kind)
    if entry is None:
        raise ApiCallError(
            ApiError(
                status=0,
                code="UnknownSignInKind",
                message=f"No sign in kind named {kind}. Known kinds: "
                f"{list(sign_in_kinds(config))}.",
                source="config",
            )
        )
    return entry


def sign_in_filter(config: Config, kind: str, app_id: str | None = None) -> str:
    """Return the OData filter for one sign in kind, optionally for one application.

    Only the beta endpoint carries signInEventTypes. The version 1.0 endpoint
    returns interactive sign ins and rejects a filter naming that property, so
    the interactive kind sends no event type clause.
    """
    entry = sign_in_entry(config, kind)
    clauses = [entry.graph_filter]
    if app_id:
        clauses.append(f"appId eq '{app_id}'")
    return " and ".join(clause for clause in clauses if clause)


def query_sign_ins_graph(
    session: Session,
    config: Config,
    *,
    kind: str = "interactive",
    app_id: str | None = None,
    failures_only: bool = False,
    top: int | None = None,
) -> tuple[SignInEvent, ...]:
    """Read sign ins of one kind through Microsoft Graph."""
    entry = sign_in_entry(config, kind)
    payloads = get_collection(
        session,
        config,
        "sign_ins",
        filter_expression=sign_in_filter(config, kind, app_id),
        limit=top or config.tables.defaults.row_limit,
        beta=entry.graph_beta,
    )
    events = tuple(project_sign_in_event(payload, config) for payload in payloads)
    log.info("read %s %s sign ins through Graph", len(events), kind)
    if failures_only:
        return tuple(event for event in events if event.failed())
    return events


def query_provisioning_graph(
    session: Session, config: Config, *, top: int | None = None
) -> tuple[dict[str, Any], ...]:
    """Read provisioning events through Microsoft Graph.

    Provisioning payloads vary widely by connector, so they are returned as
    they arrive rather than forced into a projection that would lose detail.
    """
    return get_collection(
        session,
        config,
        "provisioning",
        limit=top or config.tables.defaults.row_limit,
    )


def query_parameters(
    config: Config, *, lookback_hours: int | None = None, row_limit: int | None = None
) -> dict[str, Any]:
    """Return the KQL parameters common to every template."""
    return {
        "lookback_hours": lookback_hours or config.tables.defaults.lookback_hours,
        "row_limit": row_limit or config.tables.defaults.row_limit,
        "app_filter": "",
        "target_filter": "",
    }


def query_audit_monitor(
    client: LogsQueryClient,
    config: Config,
    workspace_id: str,
    *,
    target: str = "",
    lookback_hours: int | None = None,
    row_limit: int | None = None,
) -> tuple[AuditEvent, ...]:
    """Read directory audit events through Azure Monitor."""
    parameters = query_parameters(
        config, lookback_hours=lookback_hours, row_limit=row_limit
    )
    parameters["target_filter"] = target
    result = run_template(
        client,
        config,
        workspace_id,
        config.tables.log_queries["audit"].kql_template,
        parameters,
    )
    return audit_events_from_rows(result)


def query_sign_ins_monitor(
    client: LogsQueryClient,
    config: Config,
    workspace_id: str,
    *,
    kind: str = "interactive",
    app_id: str = "",
    lookback_hours: int | None = None,
    row_limit: int | None = None,
) -> tuple[SignInEvent, ...]:
    """Read sign ins of one kind through Azure Monitor."""
    entry = sign_in_entry(config, kind)
    parameters = query_parameters(
        config, lookback_hours=lookback_hours, row_limit=row_limit
    )
    parameters["app_filter"] = app_id
    result = run_template(client, config, workspace_id, entry.kql_template, parameters)
    return sign_in_events_from_rows(result)


def query_graph_activity(
    client: LogsQueryClient,
    config: Config,
    workspace_id: str,
    *,
    app_id: str = "",
    lookback_hours: int | None = None,
    row_limit: int | None = None,
) -> tuple[GraphActivityEvent, ...]:
    """Read Microsoft Graph activity, which exists only through Azure Monitor."""
    query = config.tables.log_queries["graph-activity"]
    parameters = query_parameters(
        config, lookback_hours=lookback_hours, row_limit=row_limit
    )
    parameters["app_filter"] = app_id
    result = run_template(client, config, workspace_id, query.kql_template, parameters)
    return graph_activity_from_rows(result)


def graph_route_available(config: Config, source: str) -> bool:
    """Return whether one log source can be read through Microsoft Graph."""
    query = config.tables.log_queries.get(source)
    return True if query is None else query.graph_supported


def explain_missing_graph_route(config: Config, source: str) -> str:
    """Return the message shown when a source has no Graph route."""
    query = config.tables.log_queries[source]
    return GRAPH_UNSUPPORTED.format(name=source, category=query.diagnostic_category)
