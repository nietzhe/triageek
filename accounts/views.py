import os

from django.conf import settings
from django.shortcuts import render

from accounts.decorators import needs_perm
from alerts.models import Alert, IngestState
from alerts.severity import describe_mapping


def _alerts_file_status(path: str) -> str:
    if not os.path.exists(path):
        return "File not found"
    if not os.access(path, os.R_OK):
        return "Exists but is not readable by this user"
    return "Readable"


@needs_perm("alerts.view_alert")
def settings_page(request):
    """Read-only view of the configuration the app is actually running with."""
    path = settings.WAZUH_ALERTS_PATH
    context = {
        "alerts_path": path,
        "alerts_file_status": _alerts_file_status(path),
        "ingest_states": IngestState.objects.order_by("path"),
        "alert_count": Alert.objects.count(),
        "demo_alert_count": Alert.objects.filter(is_demo=True).count(),
        "roles": sorted(request.user.groups.values_list("name", flat=True)),
        "severity_mapping": describe_mapping(),
        "debug": settings.DEBUG,
    }
    return render(request, "accounts/settings.html", context)
