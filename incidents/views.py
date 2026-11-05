from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from accounts.decorators import needs_perm
from alerts.models import Alert
from alerts.severity import SEVERITY_CHOICES, describe_mapping, highest_severity, severity_label

from . import services
from .models import Incident
from .services import WorkflowError

PAGE_SIZE = 50
STATUS_FILTERS = [("all", "All")] + list(Incident.Status.choices)


# --- read-only pages ----------------------------------------------------------


@needs_perm("incidents.view_incident")
def incident_list(request):
    status = request.GET.get("status", "all")
    if status not in dict(STATUS_FILTERS):
        status = "all"
    
    queryset = Incident.objects.select_related("assigned_to")
    if status != "all":
        queryset = queryset.filter(status=status)
    
    page = Paginator(queryset, PAGE_SIZE).get_page(request.GET.get("page"))
    return render(
        request,
        "incidents/list.html",
        {"page": page, "status": status, "status_choices": STATUS_FILTERS},
    )


def _alert_summary(alerts: list[Alert]) -> dict:
    return {
        "agents": sorted({a.agent_name for a in alerts if a.agent_name}),
        "rule_ids": sorted({a.rule_id for a in alerts if a.rule_id}),
        "source_ips": sorted({a.src_ip for a in alerts if a.src_ip}),
        "first_seen": alerts[0].timestamp if alerts else None,
        "last_seen": alerts[-1].timestamp if alerts else None,
    }


@needs_perm("incidents.view_incident")
def incident_detail(request, pk):
    incident = get_object_or_404(Incident.objects.select_related("assigned_to"), pk=pk)
    alerts = list(incident.alerts.order_by("timestamp", "pk"))
    allowed = services.ALLOWED_TRANSITIONS[incident.status]
    context = {
        "incident": incident,
        "alerts": alerts,
        "notes": incident.notes.select_related("author"),
        "summary": _alert_summary(alerts),
        "can_start": incident.status == Incident.Status.NEW,
        "can_return": incident.status == Incident.Status.ESCALATED,
        "can_escalate": Incident.Status.ESCALATED in allowed,
        "can_close": Incident.Status.CLOSED in allowed,
        "can_reopen": incident.status == Incident.Status.CLOSED,
        "escalation_targets": services.ESCALATION_TARGETS,
    }
    
    return render(request, "incidents/detail.html", context)


# --- write endpoints ----------------------------------------------------------


def _parse_ids(values) -> list[int]:
    ids = []
    for value in values:
        try:
            ids.append(int(value))
        except (TypeError, ValueError):
            continue
    return ids


@needs_perm("incidents.add_incident")
@require_POST
def incident_create(request):
    alerts = list(
        Alert.objects.filter(pk__in=_parse_ids(request.POST.getlist("alert_ids"))).order_by(
            "timestamp", "pk"
        )
    )
    if not alerts:
        messages.error(request, "Select at least one alert.")
        return redirect("alerts:queue")

    if "confirm" in request.POST:
        try:
            incident = services.create_incident_from_alerts(
                alerts, user=request.user, title=request.POST.get("title")
            )
        except WorkflowError as exc:
            messages.error(request, str(exc))
            return redirect("alerts:queue")
        messages.success(request, f"{incident.display_id} created.")
        return redirect(incident)

    severity = highest_severity(a.severity for a in alerts)
    context = {
        "alerts": alerts,
        "title": services.default_incident_title(alerts),
        "severity": severity,
        "severity_label": severity_label(severity),
        "mapping": describe_mapping(),
    }
    return render(request, "incidents/create.html", context)


@needs_perm("incidents.change_incident")
def incident_edit(request, pk):
    incident = get_object_or_404(Incident, pk=pk)
    users = get_user_model().objects.filter(is_active=True).order_by("username")

    if request.method == "POST":
        assigned_pk = request.POST.get("assigned_to") or None
        assignee = users.filter(pk=assigned_pk).first() if assigned_pk else None
        try:
            services.update_details(
                incident,
                user=request.user,
                title=request.POST.get("title", ""),
                severity=request.POST.get("severity", ""),
                assigned_to=assignee,
                recommended_actions=request.POST.get("recommended_actions", ""),
            )
        except WorkflowError as exc:
            messages.error(request, str(exc))
        else:
            messages.success(request, "Incident updated.")
            return redirect(incident)

    return render(
        request,
        "incidents/edit.html",
        {"incident": incident, "users": users, "severity_choices": SEVERITY_CHOICES},
    )


def _run(request, pk, action, **kwargs):
    """Run a workflow action and go back to the incident with a message."""
    incident = get_object_or_404(Incident, pk=pk)
    try:
        action(incident, user=request.user, **kwargs)
    except WorkflowError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, f"{incident.display_id} updated.")
    return redirect(incident)


@needs_perm("incidents.add_incidentnote")
@require_POST
def add_note(request, pk):
    incident = get_object_or_404(Incident, pk=pk)
    try:
        services.add_note(incident, user=request.user, text=request.POST.get("text", ""))
    except WorkflowError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, "Note added.")
    return redirect(incident)


@needs_perm("incidents.change_incident")
@require_POST
def investigate(request, pk):
    return _run(request, pk, services.start_investigating, reason=request.POST.get("reason", ""))


@needs_perm("incidents.change_incident")
@require_POST
def reopen(request, pk):
    return _run(request, pk, services.start_investigating, reason=request.POST.get("reason", ""))


@needs_perm("incidents.change_incident")
@require_POST
def escalate(request, pk):
    return _run(
        request,
        pk,
        services.escalate,
        target=request.POST.get("target", ""),
        reason=request.POST.get("reason", ""),
    )


@needs_perm("incidents.change_incident")
@require_POST
def false_positive(request, pk):
    return _run(request, pk, services.mark_false_positive, reason=request.POST.get("reason", ""))


@needs_perm("incidents.change_incident")
@require_POST
def close(request, pk):
    return _run(request, pk, services.close, reason=request.POST.get("reason", ""))
