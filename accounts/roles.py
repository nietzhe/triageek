"""Role definitions: two groups, enforced through Django permissions."""

from django.contrib.auth.models import Group, Permission

ANALYST = "analyst"
VIEWER = "viewer"

_READ_ONLY = [
    "alerts.view_alert",
    "incidents.view_incident",
    "incidents.view_incidentnote",
]

ROLE_PERMISSIONS: dict[str, list[str]] = {
    VIEWER: list(_READ_ONLY),
    ANALYST: _READ_ONLY
    + [
        "incidents.add_incident",
        "incidents.change_incident",
        "incidents.add_incidentnote",
    ],
}


class MissingPermission(Exception):
    pass


def _get_permission(dotted: str) -> Permission:
    app_label, codename = dotted.split(".", 1)
    try:
        return Permission.objects.get(content_type__app_label=app_label, codename=codename)
    except Permission.DoesNotExist as exc:
        raise MissingPermission(f"Permission {dotted} does not exist. Run `migrate` first.") from exc


def ensure_roles() -> dict[str, Group]:
    """Create (or refresh) the analyst and viewer groups. Safe to run repeatedly."""
    groups = {}
    for name, dotted_perms in ROLE_PERMISSIONS.items():
        group, _ = Group.objects.get_or_create(name=name)
        group.permissions.set([_get_permission(p) for p in dotted_perms])
        groups[name] = group
    return groups
