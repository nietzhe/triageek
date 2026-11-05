"""The single source of truth for Wazuh level -> severity.

| Wazuh level | Severity |
|-------------|----------|
| 0 to 6      | Low      |
| 7 to 9      | Medium   |
| 10 to 12    | High     |
| 13 and up   | Critical |

Templates, filters, workflow rules, reports and tests all go through this module.
"""

from collections.abc import Iterable

from django.db.models import Q

LOW = "low"
MEDIUM = "medium"
HIGH = "high"
CRITICAL = "critical"

# ascending order.
SEVERITY_ORDER = (LOW, MEDIUM, HIGH, CRITICAL)
SEVERITY_LABELS = {
    LOW: "Low",
    MEDIUM: "Medium",
    HIGH: "High",
    CRITICAL: "Critical",
}
SEVERITY_CHOICES = [(key, SEVERITY_LABELS[key]) for key in SEVERITY_ORDER]

LEVEL_BANDS = (
    (0, LOW),
    (7, MEDIUM),
    (10, HIGH),
    (13, CRITICAL),
)

def severity_for_level(level: int | None) -> str:
    if level is None:
        return LOW
    
    result = LOW
    for threshold, severity in LEVEL_BANDS:
        if level >= threshold:
            result = severity
    
    return result

def severity_label(severity: str) -> str:
    return SEVERITY_LABELS.get(severity, SEVERITY_LABELS[LOW])

def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def highest_severity(severities: Iterable[str], default: str = LOW) -> str:
    best = None
    for severity in severities:
        if best is None or severity_rank(severity) > severity_rank(best):
            best = severity
    return best if best is not None else default


def severity_filter(severity: str, field: str = "rule_level") -> Q:
    bands = list(LEVEL_BANDS)
    for index, (threshold, band_severity) in enumerate(bands):
        if band_severity != severity:
            continue
        
        upper = bands[index + 1][0] - 1 if index + 1 < len(bands) else None
        query = Q(**{f"{field}__gte": threshold})
        
        if upper is not None:
            query &= Q(**{f"{field}__lte": upper})
        
        if band_severity == severity_for_level(None):
            # include nulls for the lowest band, so that alerts with no level are 
            # still included in the "low" severity filter.
            query |= Q(**{f"{field}__isnull": True}) | Q(**{f"{field}__lt": threshold})
        
        return query
    return Q(pk__in=[])


def describe_mapping() -> str:
    parts = []
    for index, (threshold, severity) in enumerate(LEVEL_BANDS):
        if index + 1 < len(LEVEL_BANDS):
            span = f"{threshold}-{LEVEL_BANDS[index + 1][0] - 1}"
        else:
            span = f"{threshold}+"
        parts.append(f"{span} {SEVERITY_LABELS[severity]}")
    return "level " + ", ".join(parts)
