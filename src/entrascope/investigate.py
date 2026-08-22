"""Investigation: from a symptom to a cause.

The other modules answer questions. This one asks them, in the order an
engineer would, and turns the answers into findings ranked by severity.

Scope is either one application or the whole tenant. The same rules apply to
both, so a tenant wide sweep is the per application investigation run over
everything and merged.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from entrascope.config import Config, FindingRule
from entrascope.discovery import (
    discover_applications,
    discover_service_principals,
    is_first_party,
)
from entrascope.errors import explain
from entrascope.http import Session
from entrascope.logger import get_logger
from entrascope.logs import query_audit_graph, query_sign_ins_graph, sign_in_kinds
from entrascope.models import (
    SEVERITY_ORDER,
    ApiCallError,
    ApplicationSummary,
    AuditEvent,
    Finding,
    Investigation,
    ServicePrincipalSummary,
    Severity,
    SignInEvent,
)

log = get_logger(__name__)

#: Shown when the whole tenant is investigated rather than one application.
TENANT_TARGET = "the whole tenant"


def severity_of(rule: FindingRule) -> Severity:
    """Return the configured severity, defaulting to a warning."""
    if rule.severity == "error":
        return "error"
    if rule.severity == "note":
        return "note"
    return "warning"


def matches(application: ApplicationSummary, term: str) -> bool:
    """Return whether an application matches a search term.

    The term may be an application id, an object id, or part of a display name,
    because an engineer has whichever of those the error message gave them.
    """
    lowered = term.lower()
    return (
        lowered
        in (
            application.app_id.lower(),
            application.object_id.lower(),
        )
        or lowered in application.display_name.lower()
    )


def matches_principal(principal: ServicePrincipalSummary, term: str) -> bool:
    """Return whether an enterprise application matches a search term."""
    lowered = term.lower()
    return (
        lowered
        in (
            principal.app_id.lower(),
            principal.object_id.lower(),
        )
        or lowered in principal.display_name.lower()
    )


def credential_findings(
    application: ApplicationSummary, config: Config
) -> tuple[Finding, ...]:
    """Report credentials that have expired or are about to."""
    window = config.fields.expiry.warning_days
    findings: list[Finding] = []
    for credential in application.credentials:
        if credential.state == "expired":
            findings.append(
                Finding(
                    severity="error",
                    area="credential",
                    subject=application.display_name,
                    detail=(
                        f"The {credential.kind} {credential.display_name!r} expired "
                        f"on {credential.end}. Every client credentials flow using "
                        "it fails now."
                    ),
                    remediation=explain("AADSTS7000222", config).remediation,
                    docs_url=explain("AADSTS7000222", config).docs_url,
                    code="AADSTS7000222",
                )
            )
        elif credential.state == "expiring":
            findings.append(
                Finding(
                    severity="warning",
                    area="credential",
                    subject=application.display_name,
                    detail=(
                        f"The {credential.kind} {credential.display_name!r} expires "
                        f"on {credential.end}, in {credential.days_remaining} days, "
                        f"inside the {window} day warning window."
                    ),
                    remediation=explain("AADSTS7000222", config).remediation,
                    docs_url=explain("AADSTS7000222", config).docs_url,
                )
            )
    return tuple(findings)


def is_insecure(uri: str, config: Config) -> bool:
    """Return whether a redirect URI sends an authorisation code in clear."""
    rules = config.fields.findings
    if not uri.lower().startswith(rules.insecure_redirect_scheme):
        return False
    return not any(host in uri for host in rules.local_hosts)


def configuration_findings(
    application: ApplicationSummary, config: Config
) -> tuple[Finding, ...]:
    """Report configuration that will cause a failure or already explains one."""
    rules = config.fields.findings
    findings: list[Finding] = []

    if not application.owners:
        findings.append(
            Finding(
                severity=severity_of(rules.no_owner),
                area="ownership",
                subject=application.display_name,
                detail=rules.no_owner.detail.strip(),
                remediation=rules.no_owner.remediation.strip(),
                docs_url=rules.no_owner.docs_url,
            )
        )

    everything = (
        *application.redirect_uris.web,
        *application.redirect_uris.single_page,
        *application.redirect_uris.public_client,
    )
    insecure = tuple(uri for uri in everything if is_insecure(uri, config))
    if insecure:
        listed = ", ".join(insecure)
        findings.append(
            Finding(
                severity=severity_of(rules.insecure_redirect),
                area="redirect uri",
                subject=application.display_name,
                detail=f"{rules.insecure_redirect.detail.strip()} {listed}",
                remediation=rules.insecure_redirect.remediation.strip(),
                docs_url=rules.insecure_redirect.docs_url,
                occurrences=len(insecure),
            )
        )

    if application.requested_access_token_version == 1:
        findings.append(
            Finding(
                severity=severity_of(rules.token_version_one),
                area="token version",
                subject=application.display_name,
                detail=rules.token_version_one.detail.strip(),
                remediation=rules.token_version_one.remediation.strip(),
                docs_url=rules.token_version_one.docs_url,
            )
        )
    return tuple(findings)


def principal_findings(
    principal: ServicePrincipalSummary, config: Config
) -> tuple[Finding, ...]:
    """Report enterprise application settings that explain a refusal."""
    rules = config.fields.findings
    findings: list[Finding] = []
    if not principal.account_enabled:
        findings.append(
            Finding(
                severity=severity_of(rules.disabled_principal),
                area="enterprise application",
                subject=principal.display_name,
                detail=rules.disabled_principal.detail.strip(),
                remediation=rules.disabled_principal.remediation.strip(),
                docs_url=rules.disabled_principal.docs_url,
            )
        )
    if principal.app_role_assignment_required:
        findings.append(
            Finding(
                severity=severity_of(rules.assignment_required),
                area="assignment",
                subject=principal.display_name,
                detail=rules.assignment_required.detail.strip(),
                remediation=rules.assignment_required.remediation.strip(),
                docs_url=rules.assignment_required.docs_url,
            )
        )
    return tuple(findings)


def audit_findings(events: Sequence[AuditEvent], config: Config) -> tuple[Finding, ...]:
    """Report failed directory operations, grouped by what was attempted."""
    failures = tuple(
        event
        for event in events
        if event.result.lower() in config.fields.findings.audit_failure_results
    )
    grouped: dict[tuple[str, str], list[AuditEvent]] = {}
    for event in failures:
        grouped.setdefault((event.activity, event.target), []).append(event)
    findings: list[Finding] = []
    for (activity, target), group in grouped.items():
        reason = next((event.reason for event in group if event.reason), "")
        explanation = explain(reason, config) if reason else None
        findings.append(
            Finding(
                severity="error",
                area="directory operation",
                subject=target or activity,
                detail=(
                    f"{activity} failed {times(len(group))}. "
                    f"Most recent reason: {reason or 'none recorded'}."
                ),
                remediation=explanation.remediation if explanation else "",
                docs_url=explanation.docs_url if explanation else "",
                occurrences=len(group),
                code=explanation.code if explanation and explanation.known else "",
            )
        )
    return tuple(findings)


def sign_in_findings(
    events: Sequence[SignInEvent], config: Config
) -> tuple[Finding, ...]:
    """Report failed sign ins, grouped by error code and explained."""
    failures = tuple(event for event in events if event.failed())
    grouped: dict[tuple[int, str], list[SignInEvent]] = {}
    for event in failures:
        grouped.setdefault((event.error_code, event.app_display_name), []).append(event)
    findings: list[Finding] = []
    for (code, application), group in grouped.items():
        explanation = explain(f"AADSTS{code}", config)
        findings.append(
            Finding(
                severity="error",
                area="sign in",
                subject=application or "unnamed application",
                detail=(
                    f"Sign in failed {times(len(group))} with AADSTS{code}. "
                    f"{explanation.meaning} "
                    f"Most recent: {group[0].timestamp} from {group[0].ip_address}."
                ),
                remediation=explanation.remediation,
                docs_url=explanation.docs_url,
                occurrences=len(group),
                code=f"AADSTS{code}",
            )
        )
    return tuple(findings)


def rank(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    """Order findings by severity, then by how often each was seen."""
    order = {name: index for index, name in enumerate(SEVERITY_ORDER)}
    return tuple(
        sorted(
            findings,
            key=lambda item: (
                order.get(item.severity, 99),
                -item.occurrences,
                item.area,
            ),
        )
    )


def filter_by_severity(
    findings: Sequence[Finding], minimum: Severity | None
) -> tuple[Finding, ...]:
    """Return the findings at or above one severity."""
    if minimum is None:
        return tuple(findings)
    order = {name: index for index, name in enumerate(SEVERITY_ORDER)}
    ceiling = order.get(minimum, len(SEVERITY_ORDER))
    return tuple(item for item in findings if order.get(item.severity, 99) <= ceiling)


def times(count: int) -> str:
    """Render a repetition count the way a person would say it."""
    return "once" if count == 1 else f"{count} times"


def collapse_sign_in_failures(failures: Sequence[tuple[str, str]]) -> tuple[str, ...]:
    """Turn one refusal per sign in kind into one note per reason.

    A tenant without a premium licence refuses every kind for the same reason,
    and four identical notes say nothing that one does not.
    """
    by_reason: dict[str, list[str]] = {}
    for kind, reason in failures:
        by_reason.setdefault(reason, []).append(kind)
    return tuple(
        f"Sign in logs unavailable for {', '.join(sorted(kinds))}: {reason}"
        for reason, kinds in by_reason.items()
    )


def gather_logs(
    session: Session,
    config: Config,
    *,
    limit: int,
    kinds: Sequence[str] | None = None,
) -> tuple[tuple[AuditEvent, ...], tuple[SignInEvent, ...], tuple[str, ...]]:
    """Read the audit and sign in logs, tolerating a source that is unavailable.

    A tenant without a premium licence cannot read sign in logs at all, and the
    audit logs still answer, so one refusal must not empty the report. Whatever
    could not be read is recorded as a note.
    """
    notes: list[str] = []
    audit: tuple[AuditEvent, ...] = ()
    sign_ins: list[SignInEvent] = []
    refusals: list[tuple[str, str]] = []
    try:
        audit = query_audit_graph(session, config, top=limit)
    except ApiCallError as failure:
        notes.append(f"Audit logs unavailable: {failure.error.summary()}")
    for kind in kinds or sign_in_kinds(config):
        try:
            sign_ins.extend(
                query_sign_ins_graph(
                    session, config, kind=kind, failures_only=True, top=limit
                )
            )
        except ApiCallError as failure:
            refusals.append((kind, failure.error.summary()))
    notes.extend(collapse_sign_in_failures(refusals))
    return audit, tuple(sign_ins), tuple(notes)


def investigate(
    session: Session,
    config: Config,
    token: Callable[[], str] | None = None,
    *,
    target: str = "",
    limit: int = 100,
    kinds: Sequence[str] | None = None,
    minimum_severity: Severity | None = None,
    include_first_party: bool = False,
) -> Investigation:
    """Gather everything about one application, or about the whole tenant.

    With no target this sweeps the tenant, which is how an engineer starts when
    they know something is wrong but not where. With a target it narrows to one
    application, matched by application id, object id or display name.
    """
    applications = discover_applications(session, config, token)
    principals = discover_service_principals(session, config, token)
    excluded = 0
    if not include_first_party:
        kept = tuple(item for item in principals if not is_first_party(item, config))
        excluded = len(principals) - len(kept)
        principals = kept
    audit, sign_ins, notes = gather_logs(session, config, limit=limit, kinds=kinds)

    if target:
        applications = tuple(item for item in applications if matches(item, target))
        principals = tuple(
            item for item in principals if matches_principal(item, target)
        )
        wanted = {item.app_id.lower() for item in applications} | {
            item.app_id.lower() for item in principals
        }
        names = {item.display_name.lower() for item in applications} | {
            item.display_name.lower() for item in principals
        }
        sign_ins = tuple(
            event
            for event in sign_ins
            if event.app_id.lower() in wanted or event.app_display_name.lower() in names
        )
        audit = tuple(
            event
            for event in audit
            if target.lower() in event.target.lower() or event.target.lower() in names
        )

    findings = rank(
        [
            *[
                finding
                for application in applications
                for finding in (
                    *credential_findings(application, config),
                    *configuration_findings(application, config),
                )
            ],
            *[
                finding
                for principal in principals
                for finding in principal_findings(principal, config)
            ],
            *audit_findings(audit, config),
            *sign_in_findings(sign_ins, config),
        ]
    )

    log.info(
        "investigation produced %s findings",
        len(findings),
        extra={"target": target or TENANT_TARGET},
    )
    return Investigation(
        target=target or TENANT_TARGET,
        scope="application" if target else "tenant",
        applications=applications,
        service_principals=principals,
        audit_events=audit,
        sign_ins=sign_ins,
        findings=filter_by_severity(findings, minimum_severity),
        notes=(
            (
                *notes,
                f"{excluded} Microsoft first party enterprise applications "
                "were excluded. Pass --include-first-party to see them.",
            )
            if excluded
            else notes
        ),
    )
