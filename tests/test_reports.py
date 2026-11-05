from datetime import date

from django.test import TestCase
from django.urls import reverse

from incidents.models import Incident
from reports.generator import generate_report, render_markdown
from reports.periods import DAILY, MONTHLY, WEEKLY, build_period

from .helpers import make_alert, make_analyst, make_incident, make_user, utc


def incident_at(created, **kwargs):
    return make_incident(created_at=created, **kwargs)


class PeriodTests(TestCase):
    def test_daily(self):
        period = build_period(DAILY, date(2026, 11, 4))
        self.assertEqual((period.start, period.end), (utc(day=4, hour=0), utc(day=5, hour=0)))
        self.assertEqual(period.label, "4 Nov 2026")
        self.assertEqual(period.title, "Daily security report")

    def test_weekly_is_monday_to_sunday(self):
        # 2026-11-04 is a Wednesday; its week runs Mon 2 Nov to Sun 8 Nov.
        period = build_period(WEEKLY, date(2026, 11, 4))
        self.assertEqual((period.start, period.end), (utc(day=2, hour=0), utc(day=9, hour=0)))
        self.assertEqual((period.first_day, period.last_day), (date(2026, 11, 2), date(2026, 11, 8)))
        # A Monday and a Sunday belong to the same week.
        self.assertEqual(build_period(WEEKLY, date(2026, 11, 2)), period)
        self.assertEqual(build_period(WEEKLY, date(2026, 11, 8)), period)

    def test_monthly(self):
        period = build_period(MONTHLY, date(2026, 11, 30))
        self.assertEqual((period.start, period.end), (utc(day=1, hour=0), utc(month=12, day=1, hour=0)))
        december = build_period(MONTHLY, date(2026, 12, 15))
        self.assertEqual(december.end, utc(year=2027, month=1, day=1, hour=0))


class ReportCountTests(TestCase):
    def setUp(self):
        self.user = make_user("analyst1")

    def build(self, kind, day):
        return generate_report(build_period(kind, day))

    def test_daily_boundaries(self):
        incident_at(utc(day=3, hour=23, minute=59, second=59))  # previous day
        inside_start = incident_at(utc(day=4, hour=0))
        inside_end = incident_at(utc(day=4, hour=23, minute=59, second=59))
        incident_at(utc(day=5, hour=0))  # next day
        report = self.build(DAILY, date(2026, 11, 4))
        self.assertEqual({i.pk for i in report.incidents}, {inside_start.pk, inside_end.pk})

    def test_weekly_boundaries(self):
        incident_at(utc(day=1, hour=23, minute=59))  # Sunday before
        monday = incident_at(utc(day=2, hour=0))
        sunday = incident_at(utc(day=8, hour=23, minute=59))
        incident_at(utc(day=9, hour=0))  # next Monday
        report = self.build(WEEKLY, date(2026, 11, 4))
        self.assertEqual({i.pk for i in report.incidents}, {monday.pk, sunday.pk})

    def test_monthly_boundaries(self):
        incident_at(utc(month=10, day=31, hour=23, minute=59))
        first = incident_at(utc(month=11, day=1, hour=0))
        last = incident_at(utc(month=11, day=30, hour=23, minute=59))
        incident_at(utc(month=12, day=1, hour=0))
        report = self.build(MONTHLY, date(2026, 11, 15))
        self.assertEqual({i.pk for i in report.incidents}, {first.pk, last.pk})

    def test_incident_closed_in_period_is_included_once(self):
        incident = incident_at(
            utc(day=3, hour=10), status=Incident.Status.CLOSED, closed_at=utc(day=4, hour=9)
        )
        self.assertEqual([i.pk for i in self.build(DAILY, date(2026, 11, 4)).incidents], [incident.pk])
        both = incident_at(utc(day=4, hour=8), status=Incident.Status.CLOSED, closed_at=utc(day=4, hour=9))
        ids = [i.pk for i in self.build(DAILY, date(2026, 11, 4)).incidents]
        self.assertEqual(ids.count(both.pk), 1)

    def test_counts(self):
        day = utc(day=4, hour=10)
        incident_at(day, severity="high", status=Incident.Status.CLOSED, closed_at=day)
        incident_at(day, severity="medium", status=Incident.Status.CLOSED, is_false_positive=True, closed_at=day)
        incident_at(day, severity="medium", status=Incident.Status.INVESTIGATING)
        incident_at(day, severity="critical", status=Incident.Status.ESCALATED, escalated_to="L2")
        report = self.build(DAILY, date(2026, 11, 4))
        self.assertEqual(report.total, 4)
        self.assertEqual(report.false_positives, 1)
        self.assertEqual(report.closed, 1)
        self.assertEqual(report.open, 2)
        self.assertEqual(report.escalated, 1)
        rows = {r["key"]: r for r in report.severity_rows}
        self.assertEqual((rows["critical"]["total"], rows["high"]["total"], rows["medium"]["total"], rows["low"]["total"]), (1, 1, 2, 0))
        self.assertEqual(rows["medium"]["false_positive"], 1)
        self.assertIn("Four incidents were handled", report.summary)
        self.assertIn("1 critical, 1 high, 2 medium", report.summary)
        self.assertIn("1 closed, 1 classified as false positive, 2 still open (1 escalated)", report.summary)

    def test_empty_period_wording(self):
        report = self.build(DAILY, date(2026, 11, 4))
        self.assertEqual(report.total, 0)
        self.assertIn("No incidents were created or closed in the lab environment on this day.", report.summary)
        self.assertIn("No alerts were ingested", report.summary)
        self.assertEqual(report.sample_label, "")
        self.assertIn("No incidents in this period.", render_markdown(report))

    def test_alert_counts_use_alert_time(self):
        make_alert(timestamp=utc(day=4, hour=12))
        make_alert(timestamp=utc(day=5, hour=12))
        self.assertEqual(self.build(DAILY, date(2026, 11, 4)).alert_count, 1)
        self.assertEqual(self.build(WEEKLY, date(2026, 11, 4)).alert_count, 2)

    def test_recommendations_are_deduplicated(self):
        day = utc(day=4, hour=10)
        incident_at(day, recommended_actions="Disable SSH password login\nAdd fail2ban")
        incident_at(day, recommended_actions="add fail2ban\nReview auth.log")
        report = self.build(DAILY, date(2026, 11, 4))
        self.assertEqual(report.recommendations, ["Disable SSH password login", "Add fail2ban", "Review auth.log"])

    def test_outcome_uses_closing_note(self):
        from incidents import services

        incident = incident_at(utc(day=4, hour=10), status=Incident.Status.INVESTIGATING)
        services.close(incident, user=self.user, reason="no successful login")
        row = self.build(DAILY, date(2026, 11, 4)).log[0]
        self.assertEqual(row.outcome, "Closed: no successful login")

    def test_sample_data_labelling(self):
        day = utc(day=4, hour=10)
        demo_alert = make_alert(is_demo=True, timestamp=day)
        incident_at(day, alerts=[demo_alert])
        self.assertEqual(self.build(DAILY, date(2026, 11, 4)).sample_label, "Sample data")
        make_alert(is_demo=False, timestamp=day)
        self.assertEqual(self.build(DAILY, date(2026, 11, 4)).sample_label, "Includes sample data")


class ReportViewTests(TestCase):
    def setUp(self):
        self.client.force_login(make_analyst())

    def test_default_is_daily_today(self):
        response = self.client.get(reverse("reports:report"))
        self.assertContains(response, "Daily security report")
        self.assertContains(response, "Lab environment")

    def test_weekly_and_monthly_render(self):
        for kind, title in ((WEEKLY, "Weekly security report"), (MONTHLY, "Monthly security report")):
            response = self.client.get(reverse("reports:report"), {"type": kind, "date": "2026-11-04"})
            self.assertContains(response, title)

    def test_invalid_input_falls_back(self):
        response = self.client.get(reverse("reports:report"), {"type": "yearly", "date": "not-a-date"}, follow=True)
        self.assertContains(response, "Daily security report")
        self.assertContains(response, "not a valid date")

    def test_markdown_download(self):
        day = utc(day=4, hour=10)
        make_incident(created_at=day, title="Pipe | in title", recommended_actions="Do the thing")
        response = self.client.get(reverse("reports:report"), {"date": "2026-11-04", "format": "md"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertIn(".md", response["Content-Disposition"])
        body = response.content.decode()
        self.assertTrue(body.startswith("# Daily security report"))
        self.assertIn("## Incident log", body)
        self.assertIn("Pipe \\| in title", body)
        self.assertIn("- Do the thing", body)
