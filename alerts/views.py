from datetime import timedelta
from urllib.parse import urlencode
from django.core.paginator import Paginator
from django.db.models import Prefetch, Q
from django.shortcuts import render
from django.utils import timezone
from accounts.decorators import needs_perm
from incidents.models import Incident

from .models import Alert
from .severity import SEVERITY_CHOICES, describe_mapping, severity_filter

PAGE_SIZE = 50
DEFAULT_RANGE = "all"

RANGES = {
    "1h": ("Last hour", timedelta(hours = 1)),
    "24h": ("Last 24 hours", timedelta(hours = 24)),
    "7d": ("Last 7 days", timedelta(days = 7)),
    "all": ("All", None),
}

def filter_alerts(params, now = None):
    now = now or timezone.now()
    severity = params.get("severity", "all").strip().lower()
    if severity not in dict(SEVERITY_CHOICES):
        severity = "all"
    
    agent = params.get("agent", "").strip()
    range_key = params.get("range", DEFAULT_RANGE).strip().lower()
    if range_key not in RANGES:
        range_key = DEFAULT_RANGE
    
    text = params.get("q", "").strip()

    queryset = Alert.objects.all()
    if severity != "all":
        queryset = queryset.filter(severity_filter(severity))
    if agent:
        queryset = queryset.filter(agent_name = agent)
    
    window = RANGES[range_key][1]
    if window is not None:
        queryset = queryset.filter(timestamp__gte = now - window)
    if text:
        queryset = queryset.filter(
            Q(rule_id__icontains = text)
            | Q(src_ip__icontains = text)
            | Q(rule_description__icontains = text)
        )
    
    filters = {"severity": severity, "agent": agent, "range": range_key, "q": text}
    return queryset.order_by("-timestamp", "-pk"), filters


def _subtitle_agents(agents: list[str], selected: str) -> str:
    if selected:
        return selected
    if len(agents) == 1:
        return agents[0]
    if not agents:
        return ""
    return f"{len(agents)} agents"


@needs_perm("alerts.view_alert")
def queue(request):
    queryset, filters = filter_alerts(request.GET)
    queryset = queryset.prefetch_related(
        Prefetch("incidents", queryset=Incident.objects.order_by("-created_at", "-pk"))
    )

    page = Paginator(queryset, PAGE_SIZE).get_page(request.GET.get("page"))
    for alert in page:
        incidents = list(alert.incidents.all())
        alert.incident = incidents[0] if incidents else None

    agents = list(
        Alert.objects.exclude(agent_name="")
        .order_by("agent_name")
        .values_list("agent_name", flat=True)
        .distinct()
    )
    base_query = urlencode({k: v for k, v in filters.items() if v and v != "all"})

    context = {
        "page": page,
        "filters": filters,
        "agents": agents,
        "agent_subtitle": _subtitle_agents(agents, filters["agent"]),
        "severity_choices": SEVERITY_CHOICES,
        "range_choices": [(key, label) for key, (label, _) in RANGES.items()],
        "base_query": base_query,
        "mapping": describe_mapping(),
        "has_filters": bool(base_query),
    }
    return render(request, "alerts/queue.html", context)
