from datetime import date
from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone
from accounts.decorators import needs_perm

from .generator import generate_report, render_markdown
from .periods import DAILY, KIND_LABELS, KINDS, build_period


@needs_perm("incidents.view_incident")
def report(request):
    kind = request.GET.get("type", DAILY)
    if kind not in KINDS:
        kind = DAILY

    today = timezone.now().date()
    raw_date = request.GET.get("date", "").strip()
    day = today
    
    if raw_date:
        try:
            day = date.fromisoformat(raw_date)
        except ValueError:
            messages.warning(request, f"'{raw_date}' is not a valid date (use YYYY-MM-DD); showing today.")

    period = build_period(kind, day)
    data = generate_report(period)

    if request.GET.get("format") == "md":
        response = HttpResponse(render_markdown(data), content_type="text/markdown; charset=utf-8")
        filename = f"security-report-{kind}-{day.isoformat()}.md"
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        
        return response

    return render(
        request,
        "reports/report.html",
        {
            "report": data,
            "kind": kind,
            "kind_choices": [(key, KIND_LABELS[key]) for key in KINDS],
            "selected_date": day.isoformat(),
        },
    )
