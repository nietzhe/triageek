from dataclasses import dataclass, field
from django.db.models import Exists, OuterRef, Prefetch, Q
from alerts.models import Alert
from alerts.severity import SEVERITY_LABELS, SEVERITY_ORDER
from incidents.models import Incident, IncidentNote

from .periods import Period, format_day

ENVIRONMENT = "Lab environment"
_NUMBER_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"]

SEVERITIES_DESC = tuple(reversed(SEVERITY_ORDER))


@dataclass
class LogRow:
    incident: Incident
    outcome: str


@dataclass
class Report:
    period: Period
    incidents: list[Incident]
    log: list[LogRow]
    severity_rows: list[dict]  # [{"key", "label", "total", "false_positive", "open"}]
    total: int
    closed: int  # not false positive
    false_positives: int
    open: int
    escalated: int
    alert_count: int
    recommendations: list[str]
    summary: str
    sample_label: str
    subtitle_parts: list[str] = field(default_factory=list)


def _count_words(count: int) -> str:
    return _NUMBER_WORDS[count] if 0 <= count < len(_NUMBER_WORDS) else str(count)


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return singular if count == 1 else (plural or singular + "s")


def _outcome(incident: Incident) -> str:
    if incident.status == Incident.Status.CLOSED:
        notes = getattr(incident, "outcome_notes", [])
        if notes:
            return notes[-1].text
        return "False positive" if incident.is_false_positive else "Closed"
    
    if incident.status == Incident.Status.ESCALATED:
        return f"Open, escalated to {incident.escalated_to or 'L2'}"
    
    return f"Open, {incident.get_status_display().lower()}"


def _dedupe_recommendations(incidents: list[Incident]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []

    for incident in incidents:
        for action in incident.recommended_action_list:
            key = " ".join(action.lower().split())
            if key not in seen:
                seen.add(key)
                result.append(action)
    return result


def build_summary(period: Period, total, by_severity, closed, false_positives, open_, escalated, alert_count) -> str:
    when = period.when
    sentences = []
    
    if total == 0:
        sentences.append(f"No incidents were created or closed in the lab environment {when}.")
    else:
        sentences.append(
            f"{_count_words(total).capitalize()} {_plural(total, 'incident was', 'incidents were')} "
            f"handled in the lab environment {when}."
        )
        
        parts = [f"{by_severity[key]} {SEVERITY_LABELS[key].lower()}" for key in SEVERITIES_DESC if by_severity[key]]
        sentences.append("By severity: " + ", ".join(parts) + ".")
        status = f"Current status: {closed} closed, {false_positives} classified as false positive, {open_} still open"
        
        if escalated:
            status += f" ({escalated} escalated)"
        sentences.append(status + ".")
    
    if alert_count == 0:
        sentences.append(f"No alerts were ingested {when}.")
    else:
        sentences.append(f"{alert_count} {_plural(alert_count, 'alert was', 'alerts were')} ingested {when}.")
    
    return " ".join(sentences)


def generate_report(period: Period) -> Report:
    in_period = Q(created_at__gte = period.start, created_at__lt = period.end) | Q(
        closed_at__gte = period.start, closed_at__lt = period.end
    )
    
    demo_alerts = Alert.objects.filter(incidents = OuterRef("pk"), is_demo = True)
    real_alerts = Alert.objects.filter(incidents = OuterRef("pk"), is_demo = False)

    closing_notes = IncidentNote.objects.filter(
        kind__in = [IncidentNote.Kind.STATUS_CHANGE, IncidentNote.Kind.FALSE_POSITIVE]
    ).order_by("created_at", "pk")

    incidents = list(
        Incident.objects.filter(in_period)
        .annotate(has_demo=Exists(demo_alerts), has_real=Exists(real_alerts))
        .prefetch_related(Prefetch("notes", queryset=closing_notes, to_attr="outcome_notes"))
        .order_by("pk")  # by incident id
    )

    period_alerts = Alert.objects.filter(
        timestamp__gte = period.start, timestamp__lt = period.end)
    alert_count = period_alerts.count()
    demo_alert_count = period_alerts.filter(is_demo=True).count()

    by_severity = dict.fromkeys(SEVERITY_ORDER, 0)
    fp_by_severity = dict.fromkeys(SEVERITY_ORDER, 0)
    open_by_severity = dict.fromkeys(SEVERITY_ORDER, 0)

    for incident in incidents:
        by_severity[incident.severity] += 1
        
        if incident.is_false_positive:
            fp_by_severity[incident.severity] += 1
        if incident.is_open:
            open_by_severity[incident.severity] += 1

    false_positives = sum(1 for i in incidents if i.is_false_positive)
    open_ = sum(1 for i in incidents if i.is_open)
    closed = sum(1 for i in incidents if i.status == Incident.Status.CLOSED and not i.is_false_positive)
    escalated = sum(1 for i in incidents if i.status == Incident.Status.ESCALATED)

    demo_present = demo_alert_count > 0 or any(i.has_demo for i in incidents)
    real_present = (alert_count - demo_alert_count) > 0 or any(i.has_real for i in incidents)
    
    if demo_present and real_present:
        sample_label = "Includes sample data"
    elif demo_present:
        sample_label = "Sample data"
    else:
        sample_label = ""

    subtitle_parts = [period.label, ENVIRONMENT] + ([sample_label] if sample_label else [])

    return Report(
        period = period,
        incidents = incidents,
        log = [LogRow(i, _outcome(i)) for i in incidents],
        severity_rows = [
            {
                "key": key,
                "label": SEVERITY_LABELS[key],
                "total": by_severity[key],
                "false_positive": fp_by_severity[key],
                "open": open_by_severity[key],
            }
            for key in SEVERITIES_DESC
        ],
        total = len(incidents),
        closed = closed,
        false_positives = false_positives,
        open = open_,
        escalated = escalated,
        alert_count = alert_count,
        recommendations = _dedupe_recommendations(incidents),
        summary = build_summary(period, len(incidents), by_severity, closed, false_positives, open_, escalated, alert_count),
        sample_label = sample_label,
        subtitle_parts = subtitle_parts,
    )


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def render_markdown(report: Report) -> str:
    lines = [f"# {report.period.title}", "", " · ".join(report.subtitle_parts), ""]
    lines += ["## Summary", "", report.summary, ""]

    lines += ["## Incidents by severity", ""]
    lines += ["| Severity | Incidents | False positives | Still open |", "|---|---|---|---|"]
    
    for row in report.severity_rows:
        lines.append(f"| {row['label']} | {row['total']} | {row['false_positive']} | {row['open']} |")
    lines.append(f"| **Total** | **{report.total}** | **{report.false_positives}** | **{report.open}** |")
    lines.append("")

    lines += ["## Incident log", ""]
    if report.log:
        lines += ["| ID | Title | Severity | Outcome |", "|---|---|---|---|"]
        for row in report.log:
            incident = row.incident
            lines.append(
                f"| {incident.display_id} | {_cell(incident.title)} | {incident.severity_label} | {_cell(row.outcome)} |"
            )
    else:
        lines.append("No incidents in this period.")
    lines.append("")

    lines += ["## Recommendations", ""]
    if report.recommendations:
        lines += [f"- {_cell(action)}" for action in report.recommendations]
    else:
        lines.append("No recommended actions were recorded for incidents in this period.")
    lines.append("")
    lines.append(f"_Generated from the Mini SOC Lab database. Period: {format_day(report.period.first_day)}"
                 f" to {format_day(report.period.last_day)} (UTC)._")
    lines.append("")
    return "\n".join(lines)
