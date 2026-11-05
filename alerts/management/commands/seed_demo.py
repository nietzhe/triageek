# not real accidents, it's a demo to show the UI mockup. 
# all demo data is flagged is_demo=True, so you can remove it with `seed_demo --clear`.

from datetime import datetime, timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand
from django.db import transaction
from alerts.models import Alert
from alerts.severity import highest_severity
from incidents.models import Incident, IncidentNote

AGENT = "ubuntu-server"
ATTACKER_IP = "192.168.56.1"
DEMO_USER = "analyst1"

def _utc(hour: int, minute: int, second: int = 0) -> datetime:
    return datetime(2026, 11, 4, hour, minute, second, tzinfo=timezone.utc)


# key -> (time, rule id, level, description, src ip, status, full_log)
DEMO_ALERTS = {
    "550": (
        _utc(12, 29, 3), "550", 7, "Integrity checksum changed: /etc/hosts", None,
        Alert.Status.FALSE_POSITIVE,
        "File '/etc/hosts' checksum changed. (synthetic demo log)",
    ),
    "31101": (
        _utc(12, 33, 20), "31101", 5, "Web server 400 error code", ATTACKER_IP,
        Alert.Status.CLOSED,
        '192.168.56.1 - - [04/Nov/2026:12:33:20 +0000] "GET /admin HTTP/1.1" 400 226 (synthetic demo log)',
    ),
    "5710": (
        _utc(12, 40, 41), "5710", 5, "sshd: attempt to login using a non-existent user", ATTACKER_IP,
        Alert.Status.INVESTIGATING,
        "sshd[2210]: Invalid user test from 192.168.56.1 (synthetic demo log)",
    ),
    "5760": (
        _utc(12, 40, 58), "5760", 5, "sshd: authentication failed", ATTACKER_IP,
        Alert.Status.INVESTIGATING,
        "sshd[2214]: Failed password for test from 192.168.56.1 (synthetic demo log)",
    ),
    "5763": (
        _utc(12, 41, 7), "5763", 10, "sshd: brute force trying to get access to the system", ATTACKER_IP,
        Alert.Status.INVESTIGATING,
        "sshd[2214]: message repeated, possible brute force from 192.168.56.1 (synthetic demo log)",
    ),
}

DEMO_INCIDENTS = [
    {
        "title": "SSH brute force against ubuntu-server",
        "alerts": ["5710", "5760", "5763"],
        "status": Incident.Status.INVESTIGATING,
        "created": _utc(12, 42),
        "actions": [
            "Disable SSH password login",
            "Add fail2ban to sshd",
            "Review auth.log for successful logins",
        ],
        "notes": [
            (_utc(12, 45), IncidentNote.Kind.NOTE,
             "Source is the lab attacker host running Hydra against the test account. Expected activity, confirmed."),
            (_utc(12, 52), IncidentNote.Kind.NOTE,
             "No successful login in auth.log. Recommending key-only SSH and fail2ban."),
        ],
    },
    {
        "title": "Burst of web 400 errors from 192.168.56.1",
        "alerts": ["31101"],
        "status": Incident.Status.CLOSED,
        "created": _utc(12, 34),
        "closed": _utc(12, 58),
        "actions": ["Rate-limit repeated failed logins with fail2ban."],
        "notes": [
            (_utc(12, 58), IncidentNote.Kind.STATUS_CHANGE, "Closed: enumeration test from the lab attacker host."),
        ],
    },
    {
        "title": "Integrity change on /etc/hosts",
        "alerts": ["550"],
        "status": Incident.Status.CLOSED,
        "false_positive": True,
        "created": _utc(12, 30),
        "closed": _utc(12, 50),
        "actions": ["Tag planned configuration changes to reduce integrity false positives."],
        "notes": [
            (_utc(12, 50), IncidentNote.Kind.FALSE_POSITIVE, "False positive: planned change to /etc/hosts."),
        ],
    },
]


def _wazuh_like(wazuh_id: str, spec: tuple) -> dict:
    when, rule_id, level, description, src_ip, _status, full_log = spec
    raw = {
        "timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {"level": level, "description": description, "id": rule_id},
        "agent": {"id": "001", "name": AGENT},
        "id": wazuh_id,
        "full_log": full_log,
        "demo": True,
    }
    if src_ip:
        raw["data"] = {"srcip": src_ip}
    return raw


class Command(BaseCommand):
    help = "Load demo alerts (and optionally demo incidents) that mirror the UI mockup. All flagged is_demo."

    def add_arguments(self, parser):
        parser.add_argument(
            "--alerts-only",
            action="store_true",
            help="Load only the five demo alerts, all 'new', so you can triage them yourself.",
        )
        parser.add_argument("--clear", action="store_true", help="Delete all demo data and exit.")

    def handle(self, *args, **options):
        if options["clear"]:
            self._clear()
            return
        with transaction.atomic():
            created = self._create_alerts(alerts_only=options["alerts_only"])
            incidents = 0 if options["alerts_only"] else self._create_incidents()
        self.stdout.write(
            self.style.SUCCESS(
                f"Demo data ready: {created} new alert(s), {incidents} new incident(s). "
                "All flagged as demo; remove with `seed_demo --clear`."
            )
        )

    def _create_alerts(self, *, alerts_only: bool) -> int:
        created = 0
        for key, spec in DEMO_ALERTS.items():
            when, rule_id, level, description, src_ip, status, full_log = spec
            _, was_created = Alert.objects.get_or_create(
                wazuh_id=f"demo-{key}",
                defaults={
                    "timestamp": when,
                    "agent_name": AGENT,
                    "rule_id": rule_id,
                    "rule_level": level,
                    "rule_description": description,
                    "src_ip": src_ip,
                    "full_log": full_log,
                    "raw": _wazuh_like(f"demo-{key}", spec),
                    "status": Alert.Status.NEW if alerts_only else status,
                    "is_demo": True,
                },
            )
            created += was_created
        return created

    def _create_incidents(self) -> int:
        User = get_user_model()
        analyst, made = User.objects.get_or_create(username=DEMO_USER)
        if made:
            analyst.set_unusable_password()  # no known password ships with the demo
            analyst.save()
            group = Group.objects.filter(name="analyst").first()
            if group:
                analyst.groups.add(group)

        created = 0
        for spec in DEMO_INCIDENTS:
            alerts = list(Alert.objects.filter(wazuh_id__in=[f"demo-{k}" for k in spec["alerts"]]))
            if not alerts or Incident.objects.filter(alerts__in=alerts).exists():
                continue  # already seeded (or the alerts were triaged for real)
            incident = Incident.objects.create(
                title=spec["title"],
                severity=highest_severity(a.severity for a in alerts),
                status=spec["status"],
                is_false_positive=spec.get("false_positive", False),
                assigned_to=analyst,
                recommended_actions="\n".join(spec["actions"]),
                created_at=spec["created"],
                closed_at=spec.get("closed"),
            )
            incident.alerts.set(alerts)
            for when, kind, text in spec["notes"]:
                IncidentNote.objects.create(
                    incident=incident, author=analyst, kind=kind, text=text, created_at=when
                )
            created += 1
        return created

    def _clear(self):
        with transaction.atomic():
            demo_alerts = Alert.objects.filter(is_demo=True)
            # Only remove incidents that consist purely of demo alerts.
            demo_incidents = Incident.objects.filter(alerts__is_demo=True).exclude(alerts__is_demo=False)
            incident_count = demo_incidents.distinct().count()
            Incident.objects.filter(pk__in=demo_incidents.values("pk")).delete()
            alert_count, _ = demo_alerts.delete()
        self.stdout.write(
            self.style.SUCCESS(f"Removed {alert_count} demo alert(s) and {incident_count} demo incident(s).")
        )
