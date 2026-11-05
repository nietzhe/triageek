import itertools
import json
from datetime import datetime, timezone

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

from accounts.roles import ANALYST, VIEWER, ensure_roles
from alerts.models import Alert
from incidents.models import Incident

_counter = itertools.count(1)


def utc(year=2026, month=11, day=4, hour=12, minute=0, second=0) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def make_alert(**overrides) -> Alert:
    n = next(_counter)
    fields = {
        "wazuh_id": f"test-{n}",
        "timestamp": utc(),
        "agent_name": "ubuntu-server",
        "rule_id": "5763",
        "rule_level": 10,
        "rule_description": "sshd: brute force trying to get access to the system.",
        "src_ip": "192.168.56.1",
        "full_log": "log",
        "raw": {},
    }
    fields.update(overrides)
    return Alert.objects.create(**fields)


def make_user(username="alice", role=None, **extra):
    # No password: tests use force_login, and PBKDF2 hashing is very slow on small machines.
    user = get_user_model().objects.create(username=username, **extra)
    if role:
        if not Group.objects.filter(name=role).exists():
            ensure_roles()
        user.groups.add(Group.objects.get(name=role))
    return user


def make_analyst(username="analyst"):
    return make_user(username, ANALYST)


def make_viewer(username="viewer"):
    return make_user(username, VIEWER)


def make_incident(status=Incident.Status.NEW, alerts=None, **overrides) -> Incident:
    fields = {"title": "Test incident", "severity": "high", "status": status}
    fields.update(overrides)
    incident = Incident.objects.create(**fields)
    if alerts is None:
        alerts = [make_alert(status=Alert.Status.INVESTIGATING)]
    incident.alerts.set(alerts)
    return incident


def wazuh_line(**overrides) -> str:
    """One alerts.json line shaped like the sample in TASK.md."""
    obj = {
        "timestamp": "2026-11-04T12:41:07.123+0000",
        "rule": {"level": 10, "description": "sshd: brute force trying to get access to the system.", "id": "5763"},
        "agent": {"id": "001", "name": "ubuntu-server"},
        "id": "1762260067.12345",
        "full_log": "Nov  4 12:41:07 ubuntu-server sshd[1]: example",
        "data": {"srcip": "192.168.56.1"},
    }
    obj.update(overrides)
    return json.dumps({k: v for k, v in obj.items() if v is not None})
