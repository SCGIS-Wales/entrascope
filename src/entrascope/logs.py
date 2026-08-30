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
from datetime import UTC, datetime, timedelta
from re import compile as compile_pattern
from typing import Any

from azure.monitor.query import LogsQueryClient

from entrascope.config import Config, SignInKind
from entrascope.discovery import pluck, text
from entrascope.graph import get_collection, odata_literal
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
from entrascope.monitor import run_template, table_for

log = get_logger(__name__)

#: How Microsoft Graph writes a timestamp inside an OData filter: UTC, to the
#: second, with the Z that says so. An offset is rejected.
GRAPH_TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"

#: A GUID, which is the only kind of selector Graph can match an audit event
#: against. Anything else is a display name and is matched once the rows are
#: here.
OBJECT_ID = compile_pattern(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

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


def first_target(payload: Any) -> Mapping[str, Any]:
    """Return the first target of an audited operation, or an empty mapping."""
    if isinstance(payload, Sequence) and not isinstance(payload, str):
        for item in payload:
            if isinstance(item, Mapping) and (
                item.get("displayName") or item.get("id")
            ):
                return item
    return {}


def target_name(payload: Any) -> str:
    """Return the display name of the first target of an audited operation."""
    target = first_target(payload)
    return text(target.get("displayName") or target.get("id") or "")


def target_kind(payload: Any, config: Config) -> str:
    """Say what kind of object was changed, in this tool's own words.

    Graph says Application where this tool says application registration, and
    ServicePrincipal where it says enterprise application. A log line that only
    says "target" leaves the reader guessing which of the two it changed.
    """
    kind = text(first_target(payload).get("type"))
    if not kind:
        return ""
    return config.fields.classification.target_types.get(kind, kind)


def target_identifier(payload: Any) -> str:
    """Return the object id of the target, so a name is never the only handle."""
    return text(first_target(payload).get("id"))


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
        target_type=target_kind(pluck(payload, mapping["target_resources"]), config),
        target_id=target_identifier(pluck(payload, mapping["target_resources"])),
        correlation_id=text(pluck(payload, mapping["correlation_id"])),
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
        error_code=whole_number(error_code),
        failure_reason=text(pluck(payload, mapping["failure_reason"])),
        correlation_id=text(pluck(payload, mapping["correlation_id"])),
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


def whole_number(value: Any) -> int:
    """Coerce a log cell into a whole number, treating nonsense as zero.

    Log Analytics types a column by what it found, so a duration arrives as a
    float and a result code as a string. Neither is a reason to lose the whole
    result set, which is what an unguarded int() over one cell of one row
    does: a single odd value and nothing is reported at all.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(float(str(value).strip()))
    except TypeError, ValueError:
        log.debug("a numeric log column held %r, reading it as zero", value)
        return 0


def audit_events_from_rows(
    result: QueryResult, config: Config | None = None
) -> tuple[AuditEvent, ...]:
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
            # TargetName is projected by the template. Where it is absent the
            # raw TargetResources array is there instead, and rendering that
            # whole array as the name of one target is unreadable, so the same
            # helper the Graph route uses picks the name out of it.
            target=text(row_value(row, "TargetName"))
            or target_name(row_value(row, "TargetResources")),
            target_type=(
                target_kind(row_value(row, "TargetResources"), config)
                if config is not None
                else ""
            ),
            target_id=text(row_value(row, "TargetId"))
            or target_identifier(row_value(row, "TargetResources")),
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
            error_code=whole_number(row_value(row, "ResultType")),
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
            status=whole_number(row_value(row, "ResponseStatusCode")),
            uri=text(row_value(row, "RequestUri")),
            roles=text(row_value(row, "Roles")),
            scopes=text(row_value(row, "Scopes")),
            duration_ms=whole_number(row_value(row, "DurationMs")),
            request_id=text(row_value(row, "RequestId")),
        )
        for row in result.as_dicts()
    )


def audit_categories(config: Config) -> tuple[str, ...]:
    """Return the audit categories that can be asked for, by name."""
    return tuple(sorted(config.tables.audit_categories))


def audit_category_value(config: Config, category: str | None) -> str:
    """Return the Graph value for one named category, or explain what exists.

    The name is this tool's, the value is Microsoft's, and the mapping is
    configuration. An empty value means every category, which is a real answer
    rather than a missing one.
    """
    wanted = category or config.tables.default_audit_category
    if wanted not in config.tables.audit_categories:
        raise ApiCallError(
            ApiError(
                status=0,
                code="UnknownAuditCategory",
                message=(
                    f"No audit category named {wanted}. Known categories: "
                    f"{list(audit_categories(config))}."
                ),
                source="config",
            )
        )
    return config.tables.audit_categories[wanted]


def since_timestamp(lookback_hours: int, now: datetime | None = None) -> str:
    """Return the start of a lookback window, as Graph writes a timestamp.

    Graph compares a datetime literal in an OData filter without quoting it,
    and rejects one carrying an offset, so it is rendered in UTC with the
    trailing Z that means exactly that.
    """
    moment = (now or datetime.now(UTC)) - timedelta(hours=lookback_hours)
    return moment.astimezone(UTC).strftime(GRAPH_TIMESTAMP)


def joined(clauses: Sequence[str]) -> str:
    """Return the clauses that say something, joined into one OData filter."""
    return " and ".join(clause for clause in clauses if clause)


def audit_filter(
    config: Config,
    category: str | None = None,
    *,
    target: str = "",
    lookback_hours: int | None = None,
    now: datetime | None = None,
) -> str:
    """Return the OData filter for the audit log.

    Every clause is applied at Microsoft Graph. A filter applied after the rows
    arrive can only narrow the newest rows, so an application last changed a
    month ago would look like one that was never changed at all.
    """
    query = config.tables.log_queries["audit"]
    value = audit_category_value(config, category)
    clauses = [query.graph_filter_template.format(category=value) if value else ""]
    if lookback_hours and query.graph_since_template:
        clauses.append(
            query.graph_since_template.format(
                since=since_timestamp(lookback_hours, now)
            )
        )
    # Only an object id can be matched at Graph. Anything else is a name, and
    # the caller narrows on that once the rows are here.
    if target and query.graph_target_template and looks_like_identifier(target):
        clauses.append(query.graph_target_template.format(target=odata_literal(target)))
    return joined(clauses)


def looks_like_identifier(value: str) -> bool:
    """Return whether a selector is an object id rather than a name."""
    return bool(OBJECT_ID.match(value))


def matches_target(event: AuditEvent, selector: str) -> bool:
    """Return whether an audit event concerns the thing that was asked for."""
    lowered = selector.lower()
    return (
        lowered in event.target.lower()
        or lowered == event.target_id.lower()
        or lowered in event.activity.lower()
    )


def query_audit_graph(
    session: Session,
    config: Config,
    *,
    category: str | None = None,
    target: str = "",
    lookback_hours: int | None = None,
    top: int | None = None,
) -> tuple[AuditEvent, ...]:
    """Read directory audit events through Microsoft Graph.

    The category, the period and, where the selector is an object id, the
    object are all narrowed at Graph. A selector that is a display name cannot
    be, so it is applied here, and the caller is told which happened.
    """
    query = config.tables.log_queries["audit"]
    defaults = config.tables.defaults
    payloads = get_collection(
        session,
        config,
        "directory_audits",
        filter_expression=audit_filter(
            config,
            category,
            target=target,
            lookback_hours=lookback_hours or defaults.lookback_hours,
        ),
        limit=top or defaults.row_limit,
        order_by=query.graph_order_by,
    )
    events = tuple(project_audit_event(payload, config) for payload in payloads)
    if target and not looks_like_identifier(target):
        events = tuple(event for event in events if matches_target(event, target))
    log.info("read %s audit events through Graph", len(events))
    return events


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


def sign_in_filter(
    config: Config,
    kind: str,
    app_id: str | None = None,
    *,
    failures_only: bool = False,
    lookback_hours: int | None = None,
    now: datetime | None = None,
) -> str:
    """Return the OData filter for one sign in kind.

    Only the beta endpoint carries signInEventTypes. The version 1.0 endpoint
    returns interactive sign ins and rejects a filter naming that property, so
    the interactive kind sends no event type clause.

    Every other clause is applied here rather than after the rows arrive.
    Asking for the newest twenty five sign ins and then keeping the failures
    answers "were any of the newest twenty five a failure", which is not the
    question anybody asked.
    """
    entry = sign_in_entry(config, kind)
    filters = config.tables.sign_in_filters
    clauses = [entry.graph_filter]
    if app_id and filters.graph_app_template:
        clauses.append(filters.graph_app_template.format(app_id=odata_literal(app_id)))
    if failures_only:
        clauses.append(filters.graph_failures_filter)
    if lookback_hours and filters.graph_since_template:
        clauses.append(
            filters.graph_since_template.format(
                since=since_timestamp(lookback_hours, now)
            )
        )
    return joined(clauses)


def query_sign_ins_graph(
    session: Session,
    config: Config,
    *,
    kind: str = "interactive",
    app_id: str | None = None,
    failures_only: bool = False,
    lookback_hours: int | None = None,
    top: int | None = None,
) -> tuple[SignInEvent, ...]:
    """Read sign ins of one kind through Microsoft Graph."""
    entry = sign_in_entry(config, kind)
    defaults = config.tables.defaults
    payloads = get_collection(
        session,
        config,
        "sign_ins",
        filter_expression=sign_in_filter(
            config,
            kind,
            app_id,
            failures_only=failures_only,
            lookback_hours=lookback_hours or defaults.lookback_hours,
        ),
        limit=top or defaults.row_limit,
        beta=entry.graph_beta,
        order_by=config.tables.sign_in_filters.graph_order_by,
    )
    events = tuple(project_sign_in_event(payload, config) for payload in payloads)
    log.info("read %s %s sign ins through Graph", len(events), kind)
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


def within(value: int, ceiling: int, what: str) -> int:
    """Return a number inside its bounds, saying so when it was not.

    These reach a KQL query as numbers rather than as text, so nothing can be
    injected through them. What they can do is ask a workspace for ten million
    rows, which is a way to hang a terminal rather than to read a log.
    """
    if value < 1:
        log.warning("%s of %s is not a number of anything, using 1", what, value)
        return 1
    if value > ceiling:
        log.warning("%s of %s is above the ceiling of %s", what, value, ceiling)
        return ceiling
    return value


def query_parameters(
    config: Config, *, lookback_hours: int | None = None, row_limit: int | None = None
) -> dict[str, Any]:
    """Return the KQL parameters common to every template.

    Every template is given every common parameter whether it names one or not,
    so that adding a clause to a template is a change to that file alone.
    """
    defaults = config.tables.defaults
    return {
        "lookback_hours": within(
            lookback_hours or defaults.lookback_hours,
            defaults.max_lookback_hours,
            "a lookback",
        ),
        "row_limit": within(
            row_limit or defaults.row_limit, defaults.max_row_limit, "a row limit"
        ),
        "app_filter": "",
        "target_filter": "",
        "category": "",
        "failures_only": 0,
    }


def query_audit_monitor(
    client: LogsQueryClient,
    config: Config,
    workspace_id: str,
    *,
    category: str | None = None,
    target: str = "",
    lookback_hours: int | None = None,
    row_limit: int | None = None,
) -> tuple[AuditEvent, ...]:
    """Read directory audit events through Azure Monitor.

    The same category names the Graph route takes, so the two routes answer the
    same question and the choice between them is about retention rather than
    about what can be asked.
    """
    parameters = query_parameters(
        config, lookback_hours=lookback_hours, row_limit=row_limit
    )
    parameters["target_filter"] = target
    parameters["category"] = audit_category_value(config, category)
    result = run_template(
        client,
        config,
        workspace_id,
        config.tables.log_queries["audit"].kql_template,
        parameters,
    )
    return audit_events_from_rows(result, config)


def query_sign_ins_monitor(
    client: LogsQueryClient,
    config: Config,
    workspace_id: str,
    *,
    kind: str = "interactive",
    app_id: str = "",
    failures_only: bool = False,
    lookback_hours: int | None = None,
    row_limit: int | None = None,
) -> tuple[SignInEvent, ...]:
    """Read sign ins of one kind through Azure Monitor.

    The table comes from the kind, because each kind is exported to a table of
    its own, and whether to keep only the failures is asked of the workspace
    rather than applied to whatever came back.
    """
    entry = sign_in_entry(config, kind)
    parameters = query_parameters(
        config, lookback_hours=lookback_hours, row_limit=row_limit
    )
    parameters["app_filter"] = app_id
    parameters["failures_only"] = 1 if failures_only else 0
    result = run_template(
        client,
        config,
        workspace_id,
        entry.kql_template,
        parameters,
        identifiers={"table": table_for(config, entry.diagnostic_category)},
    )
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
