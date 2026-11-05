from django import template
from django.utils.html import format_html

from alerts.severity import SEVERITY_LABELS, severity_label

register = template.Library()

@register.simple_tag
def severity_pill(severity: str):
    key = severity if severity in SEVERITY_LABELS else "low"
    return format_html('<span class="pill pill-{}">{}</span>', key, severity_label(key))
