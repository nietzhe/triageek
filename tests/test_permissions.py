from django.test import TestCase
from django.urls import reverse

from incidents.models import Incident, IncidentNote

from .helpers import make_alert, make_analyst, make_incident, make_user, make_viewer


class AccessTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.analyst = make_analyst()
        cls.viewer = make_viewer()
        cls.alert = make_alert()
        cls.incident = make_incident(status=Incident.Status.INVESTIGATING)
        pk = cls.incident.pk
        cls.read_urls = [
            reverse("alerts:queue"),
            reverse("incidents:list"),
            reverse("incidents:detail", args=[pk]),
            reverse("reports:report"),
            reverse("accounts:settings"),
        ]
        # (url, method) pairs: every endpoint that changes data or shows a write form.
        cls.write_endpoints = [
            (reverse("incidents:create"), "post", {"alert_ids": [cls.alert.pk]}),
            (reverse("incidents:edit", args=[pk]), "get", {}),
            (reverse("incidents:edit", args=[pk]), "post", {"title": "x", "severity": "low"}),
            (reverse("incidents:add_note", args=[pk]), "post", {"text": "hello"}),
            (reverse("incidents:investigate", args=[pk]), "post", {}),
            (reverse("incidents:escalate", args=[pk]), "post", {"target": "L2", "reason": "r"}),
            (reverse("incidents:false_positive", args=[pk]), "post", {"reason": "r"}),
            (reverse("incidents:close", args=[pk]), "post", {"reason": "r"}),
            (reverse("incidents:reopen", args=[pk]), "post", {}),
        ]

    def test_anonymous_is_redirected_to_login_everywhere(self):
        login = reverse("login")
        for url in self.read_urls + [u for u, _, _ in self.write_endpoints]:
            for method in ("get", "post"):
                with self.subTest(url=url, method=method):
                    response = getattr(self.client, method)(url)
                    self.assertEqual(response.status_code, 302)
                    self.assertTrue(response["Location"].startswith(login))

    def test_login_page_is_public(self):
        self.assertEqual(self.client.get(reverse("login")).status_code, 200)

    def test_viewer_can_read(self):
        self.client.force_login(self.viewer)
        for url in self.read_urls:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)

    def test_viewer_gets_403_on_every_write_endpoint(self):
        self.client.force_login(self.viewer)
        before = (Incident.objects.count(), IncidentNote.objects.count())
        for url, method, data in self.write_endpoints:
            with self.subTest(url=url, method=method):
                self.assertEqual(getattr(self.client, method)(url, data).status_code, 403)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, Incident.Status.INVESTIGATING)
        self.assertEqual((Incident.objects.count(), IncidentNote.objects.count()), before)

    def test_viewer_does_not_see_write_buttons(self):
        self.client.force_login(self.viewer)
        detail = self.client.get(reverse("incidents:detail", args=[self.incident.pk])).content.decode()
        for label in ("Escalate to L2", "Mark false positive", "Close incident", "Add note"):
            self.assertNotIn(label, detail)
        queue = self.client.get(reverse("alerts:queue")).content.decode()
        self.assertNotIn("Create incident from selected", queue)

    def test_analyst_sees_write_buttons_and_can_write(self):
        self.client.force_login(self.analyst)
        detail = self.client.get(reverse("incidents:detail", args=[self.incident.pk])).content.decode()
        for label in ("Escalate to L2", "Mark false positive", "Close incident", "Add note"):
            self.assertIn(label, detail)
        response = self.client.post(reverse("incidents:add_note", args=[self.incident.pk]), {"text": "hello"})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.incident.notes.filter(text="hello", author=self.analyst).exists())

    def test_user_without_a_role_has_no_access(self):
        self.client.force_login(make_user("norole"))
        self.assertEqual(self.client.get(reverse("alerts:queue")).status_code, 403)

    def test_writes_require_post(self):
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.get(reverse("incidents:close", args=[self.incident.pk])).status_code, 405)

    def test_csrf_is_enforced_on_posts(self):
        from django.test import Client

        client = Client(enforce_csrf_checks=True)
        client.force_login(self.analyst)
        response = client.post(reverse("incidents:add_note", args=[self.incident.pk]), {"text": "x"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.incident.notes.filter(text="x").exists())


class WorkflowViewTests(TestCase):
    """The analyst's path through the UI endpoints, including rule violations."""

    def setUp(self):
        self.analyst = make_analyst()
        self.client.force_login(self.analyst)

    def test_create_from_selection_two_step(self):
        alerts = [make_alert(), make_alert(rule_level=5, rule_id="5760")]
        ids = [a.pk for a in alerts]
        first = self.client.post(reverse("incidents:create"), {"alert_ids": ids})
        self.assertEqual(first.status_code, 200)
        self.assertContains(first, "brute force")
        self.assertEqual(Incident.objects.count(), 0)

        second = self.client.post(
            reverse("incidents:create"), {"alert_ids": ids, "confirm": "1", "title": "My incident"}
        )
        incident = Incident.objects.get()
        self.assertRedirects(second, incident.get_absolute_url())
        self.assertEqual(incident.title, "My incident")

    def test_create_without_selection(self):
        response = self.client.post(reverse("incidents:create"), {}, follow=True)
        self.assertContains(response, "Select at least one alert")

    def test_close_without_reason_shows_error_and_changes_nothing(self):
        incident = make_incident(status=Incident.Status.INVESTIGATING)
        response = self.client.post(reverse("incidents:close", args=[incident.pk]), {"reason": ""}, follow=True)
        self.assertContains(response, "requires a reason")
        incident.refresh_from_db()
        self.assertEqual(incident.status, Incident.Status.INVESTIGATING)

    def test_full_path_from_alert_to_closed(self):
        alert = make_alert()
        self.client.post(reverse("incidents:create"), {"alert_ids": [alert.pk], "confirm": "1", "title": "T"})
        incident = Incident.objects.get()
        self.client.post(reverse("incidents:investigate", args=[incident.pk]))
        self.client.post(reverse("incidents:add_note", args=[incident.pk]), {"text": "looked at it"})
        self.client.post(reverse("incidents:close", args=[incident.pk]), {"reason": "benign"})
        incident.refresh_from_db()
        alert.refresh_from_db()
        self.assertEqual(incident.status, Incident.Status.CLOSED)
        self.assertEqual(alert.status, "closed")
        self.assertEqual(incident.notes.count(), 4)
        page = self.client.get(incident.get_absolute_url())
        self.assertContains(page, "Closed: benign")

    def test_alert_text_is_escaped(self):
        make_alert(rule_description="<script>alert(1)</script>")
        response = self.client.get(reverse("alerts:queue"))
        self.assertNotContains(response, "<script>alert(1)</script>")
        self.assertContains(response, "&lt;script&gt;alert(1)&lt;/script&gt;")
