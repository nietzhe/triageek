from collections.abc import Iterable
from django.db import transaction
from django.utils import timezone
from alerts.models import Alert
from alerts.severity import SEVERITY_LABELS, highest_severity

from .models import Incident, IncidentNote

Status = Incident.Status
Kind = IncidentNote.Kind

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    Status.NEW: {Status.INVESTIGATING, Status.ESCALATED, Status.CLOSED},
    Status.INVESTIGATING: {Status.ESCALATED, Status.CLOSED},
    Status.ESCALATED: {Status.INVESTIGATING, Status.CLOSED},
    Status.CLOSED: {Status.INVESTIGATING},
}
ESCALATION_TARGETS = ("L2",)
MAX_TITLE_LENGTH = 200


class WorkflowError(Exception):
    """a business rule was violated. The message is safe to show to the analyst."""


# helpers
def can_transition(current: str, target: str) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, set())

def _require_transition(incident: Incident, target: str) -> None:
    if not can_transition(incident.status, target):
        raise WorkflowError(
            f"An incident that is {incident.get_status_display().lower()} cannot move to "
            f"{Status(target).label.lower()}."
        )

def _require_text(value: str | None, message: str) -> str:
    value = (value or "").strip()
    if not value:
        raise WorkflowError(message)
    return value

def _log(incident: Incident, user, kind: str, text: str) -> IncidentNote:
    return IncidentNote.objects.create(incident=incident, author=user, kind=kind, text=text)

def _set_alert_status(incident: Incident, status: str) -> None:
    incident.alerts.update(status=status)

def normalize_actions(text: str | None) -> str:
    return "\n".join(line.strip() for line in (text or "").splitlines() if line.strip())


# creating a new incident from alerts, and editing an existing incident.
def default_incident_title(alerts: Iterable[Alert]) -> str:
    alerts = list(alerts)
    if not alerts:
        return ""
    
    top = max(
        alerts,
        key=lambda a: (a.rule_level if a.rule_level is not None else -1, a.timestamp),
    )
    
    description = (top.rule_description or f"Rule {top.rule_id}" or "Alert").strip().rstrip(".")
    src_ip = top.src_ip or next((a.src_ip for a in alerts if a.src_ip), None)
    title = f"{description} from {src_ip}" if src_ip else description
    
    return title[:MAX_TITLE_LENGTH]

@transaction.atomic
def create_incident_from_alerts(alerts: Iterable[Alert], *, user, title: str | None = None) -> Incident:
    alerts = list(alerts)
    if not alerts:
        raise WorkflowError("Select at least one alert.")
    
    not_new = [a for a in alerts if a.status != Alert.Status.NEW]
    if not_new:
        raise WorkflowError(
            f"{len(not_new)} selected alert(s) were already triaged; only new alerts can be "
            "added to a new incident."
        )

    title = (title or "").strip()[:MAX_TITLE_LENGTH] or default_incident_title(alerts)
    incident = Incident.objects.create(
        title=title,
        severity=highest_severity(a.severity for a in alerts),
        status=Status.NEW,
        assigned_to=user,
    )
    incident.alerts.set(alerts)
    Alert.objects.filter(pk__in=[a.pk for a in alerts]).update(status=Alert.Status.INVESTIGATING)
    _log(incident, user, Kind.STATUS_CHANGE, f"Incident created from {len(alerts)} alert(s).")
    
    return incident


# editing details, adding notes, and changing state.
@transaction.atomic
def update_details(
    incident: Incident, *, user, title: str, severity: str, assigned_to, recommended_actions: str
) -> Incident:
    title = _require_text(title, "The title cannot be empty.")[:MAX_TITLE_LENGTH]
    if severity not in SEVERITY_LABELS:
        raise WorkflowError("Unknown severity.")

    if severity != incident.severity:
        _log(
            incident,
            user,
            Kind.NOTE,
            f"Severity changed from {SEVERITY_LABELS.get(incident.severity, incident.severity)} "
            f"to {SEVERITY_LABELS[severity]}.",
        )
    if assigned_to != incident.assigned_to:
        who = assigned_to.get_username() if assigned_to else "nobody"
        _log(incident, user, Kind.NOTE, f"Assigned to {who}.")

    incident.title = title
    incident.severity = severity
    incident.assigned_to = assigned_to
    incident.recommended_actions = normalize_actions(recommended_actions)
    incident.save()
    return incident

@transaction.atomic
def add_note(incident: Incident, *, user, text: str) -> IncidentNote:
    text = _require_text(text, "A note cannot be empty.")
    return _log(incident, user, Kind.NOTE, text)


# state changes -- investigating, escalated, closed, false positive
@transaction.atomic
def start_investigating(incident: Incident, *, user, reason: str = "") -> Incident:
    _require_transition(incident, Status.INVESTIGATING)
    previous = incident.status
    reason = (reason or "").strip()

    incident.status = Status.INVESTIGATING
    incident.escalated_to = ""
    incident.is_false_positive = False
    incident.closed_at = None
    incident.save()
    _set_alert_status(incident, Alert.Status.INVESTIGATING)

    if previous == Status.CLOSED:
        text = "Reopened incident."
    elif previous == Status.ESCALATED:
        text = "Returned from escalation to investigating."
    else:
        text = "Status changed from New to Investigating."
    
    if reason:
        text = f"{text} Reason: {reason}"
    _log(incident, user, Kind.STATUS_CHANGE, text)
    
    return incident

@transaction.atomic
def escalate(incident: Incident, *, user, target: str, reason: str) -> Incident:
    target = (target or "").strip()
    if target not in ESCALATION_TARGETS:
        raise WorkflowError(f"Choose an escalation target ({', '.join(ESCALATION_TARGETS)}).")
    
    reason = _require_text(reason, "Escalating requires a reason.")
    _require_transition(incident, Status.ESCALATED)

    incident.status = Status.ESCALATED
    incident.escalated_to = target
    incident.save()
    
    _set_alert_status(incident, Alert.Status.INVESTIGATING)
    _log(incident, user, Kind.ESCALATION, f"Escalated to {target}: {reason}")
    
    return incident


@transaction.atomic
def close(incident: Incident, *, user, reason: str) -> Incident:
    reason = _require_text(reason, "Closing an incident requires a reason note.")
    _require_transition(incident, Status.CLOSED)

    incident.status = Status.CLOSED
    incident.is_false_positive = False
    incident.closed_at = timezone.now()
    incident.save()
    
    _set_alert_status(incident, Alert.Status.CLOSED)
    _log(incident, user, Kind.STATUS_CHANGE, f"Closed: {reason}")
    
    return incident

@transaction.atomic
def mark_false_positive(incident: Incident, *, user, reason: str) -> Incident:
    reason = _require_text(reason, "Marking a false positive requires a reason note.")
    _require_transition(incident, Status.CLOSED)

    incident.status = Status.CLOSED
    incident.is_false_positive = True
    incident.closed_at = timezone.now()
    incident.save()
    
    _set_alert_status(incident, Alert.Status.FALSE_POSITIVE)
    _log(incident, user, Kind.FALSE_POSITIVE, f"False positive: {reason}")
    
    return incident
