from datetime import timedelta
from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from alerts.models import Alert
from incidents.models import Incident

from .helpers import make_alert, make_analyst, make_viewer


class AlertQueueFilterTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.critical = make_alert(rule_id="9001", rule_level=14, rule_description="Critical thing", timestamp=now - timedelta(minutes=10), src_ip="10.0.0.1")
        cls.high = make_alert(rule_id="5763", rule_level=10, rule_description="sshd: brute force", timestamp=now - timedelta(minutes=30), src_ip="192.168.56.1")
        cls.medium = make_alert(rule_id="550", rule_level=7, rule_description="Integrity checksum changed", timestamp=now - timedelta(hours=5), agent_name="web-01", src_ip=None)
        cls.low = make_alert(rule_id="5760", rule_level=5, rule_description="sshd: authentication failed", timestamp=now - timedelta(days=3), src_ip="192.168.56.1")
        cls.old = make_alert(rule_id="31101", rule_level=5, rule_description="Web server 400 error code", timestamp=now - timedelta(days=30), agent_name="web-01", src_ip="172.16.0.5")

    def setUp(self):
        self.client.force_login(make_analyst())

    def rows(self, **params):
        response = self.client.get(reverse("alerts:queue"), params)
        self.assertEqual(response.status_code, 200)
        return [alert.pk for alert in response.context["page"]]

    def test_default_shows_everything_newest_first(self):
        self.assertEqual(self.rows(), [self.critical.pk, self.high.pk, self.medium.pk, self.low.pk, self.old.pk])

    def test_severity(self):
        self.assertEqual(self.rows(severity="critical"), [self.critical.pk])
        self.assertEqual(self.rows(severity="high"), [self.high.pk])
        self.assertEqual(self.rows(severity="medium"), [self.medium.pk])
        self.assertEqual(self.rows(severity="low"), [self.low.pk, self.old.pk])
        self.assertEqual(len(self.rows(severity="all")), 5)

    def test_agent(self):
        self.assertEqual(self.rows(agent="web-01"), [self.medium.pk, self.old.pk])

    def test_range(self):
        self.assertEqual(self.rows(range="1h"), [self.critical.pk, self.high.pk])
        self.assertEqual(self.rows(range="24h"), [self.critical.pk, self.high.pk, self.medium.pk])
        self.assertEqual(self.rows(range="7d"), [self.critical.pk, self.high.pk, self.medium.pk, self.low.pk])
        self.assertEqual(len(self.rows(range="all")), 5)

    def test_search_by_rule_ip_and_text(self):
        self.assertEqual(self.rows(q="5763"), [self.high.pk])
        self.assertEqual(self.rows(q="172.16"), [self.old.pk])
        self.assertEqual(self.rows(q="192.168.56.1"), [self.high.pk, self.low.pk])
        self.assertEqual(self.rows(q="INTEGRITY"), [self.medium.pk])

    def test_filters_combine(self):
        self.assertEqual(self.rows(severity="low", q="sshd"), [self.low.pk])
        self.assertEqual(self.rows(agent="web-01", range="24h"), [self.medium.pk])

    def test_invalid_values_are_ignored(self):
        self.assertEqual(len(self.rows(severity="bogus", range="forever")), 5)

    def test_pagination(self):
        for _ in range(60):
            make_alert()
        response = self.client.get(reverse("alerts:queue"))
        self.assertEqual(len(response.context["page"]), 50)
        self.assertEqual(response.context["page"].paginator.num_pages, 2)
        response = self.client.get(reverse("alerts:queue"), {"page": 2, "severity": "high"})
        self.assertContains(response, "severity=high")

    def test_filters_persist_in_the_form(self):
        response = self.client.get(reverse("alerts:queue"), {"severity": "high", "q": "ssh"})
        self.assertContains(response, 'value="ssh"')
        self.assertContains(response, '<option value="high" selected>')

    def test_footnote_and_columns(self):
        response = self.client.get(reverse("alerts:queue"))
        self.assertContains(response, "Severity mapping: level 0-6 Low, 7-9 Medium, 10-12 High, 13+ Critical.")
        for heading in ("Time (UTC)", "Severity", "Level", "Rule", "Description", "Source IP", "Status"):
            self.assertContains(response, f"<th>{heading}</th>", html=True)

    def test_status_column_links_incident(self):
        incident = Incident.objects.create(title="T", severity="high")
        self.high.status = Alert.Status.INVESTIGATING
        self.high.save()
        incident.alerts.add(self.high)
        response = self.client.get(reverse("alerts:queue"))
        self.assertContains(response, f'Investigating (<a href="{incident.get_absolute_url()}">{incident.display_id}</a>)', html=True)

    def test_only_new_alerts_are_selectable(self):
        self.high.status = Alert.Status.CLOSED
        self.high.save()
        response = self.client.get(reverse("alerts:queue"))
        self.assertNotContains(response, f'value="{self.high.pk}"')
        self.assertContains(response, f'value="{self.critical.pk}"')


class DemoDataTests(TestCase):
    def test_sidebar_note_only_when_demo_data_exists(self):
        self.client.force_login(make_viewer())
        self.assertNotContains(self.client.get(reverse("alerts:queue")), "Sample lab data")
        call_command("seed_demo", stdout=StringIO())
        self.assertContains(self.client.get(reverse("alerts:queue")), "Sample lab data")

    def test_seed_is_idempotent_and_flagged(self):
        for _ in range(2):
            call_command("seed_demo", stdout=StringIO())
        self.assertEqual(Alert.objects.count(), 5)
        self.assertFalse(Alert.objects.filter(is_demo=False).exists())
        self.assertEqual(Incident.objects.count(), 3)

    def test_alerts_only_option(self):
        call_command("seed_demo", alerts_only=True, stdout=StringIO())
        self.assertEqual(Incident.objects.count(), 0)
        self.assertEqual(set(Alert.objects.values_list("status", flat=True)), {"new"})

    def test_demo_not_mixed_silently_and_clear_keeps_real_data(self):
        real = make_alert()
        call_command("seed_demo", stdout=StringIO())
        call_command("seed_demo", clear=True, stdout=StringIO())
        self.assertEqual(list(Alert.objects.all()), [real])
        self.assertEqual(Incident.objects.count(), 0)

    def test_daily_report_from_demo_data(self):
        call_command("seed_demo", stdout=StringIO())
        self.client.force_login(make_viewer())
        response = self.client.get(reverse("reports:report"), {"date": "2026-11-04"})
        self.assertContains(response, "Three incidents were handled")
        self.assertContains(response, "Sample data")
        self.assertContains(response, "SSH brute force against ubuntu-server")
        self.assertContains(response, "Tag planned configuration changes")
        self.assertContains(response, "Open, investigating")
        self.assertContains(response, "False positive: planned change to /etc/hosts.")
