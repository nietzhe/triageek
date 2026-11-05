from django.test import TestCase

from alerts.models import Alert
from incidents import services
from incidents.models import Incident, IncidentNote
from incidents.services import WorkflowError

from .helpers import make_alert, make_incident, make_user

S = Incident.Status

# What each target state means as a service call.
ACTIONS = {
    S.INVESTIGATING: lambda i, u: services.start_investigating(i, user=u),
    S.ESCALATED: lambda i, u: services.escalate(i, user=u, target="L2", reason="needs L2"),
    S.CLOSED: lambda i, u: services.close(i, user=u, reason="done"),
}

ALLOWED = {
    S.NEW: {S.INVESTIGATING, S.ESCALATED, S.CLOSED},
    S.INVESTIGATING: {S.ESCALATED, S.CLOSED},
    S.ESCALATED: {S.INVESTIGATING, S.CLOSED},
    S.CLOSED: {S.INVESTIGATING},
}


class CreateIncidentTests(TestCase):
    def setUp(self):
        self.user = make_user("analyst1")

    def test_defaults_from_alerts(self):
        low = make_alert(rule_level=5, rule_description="sshd: authentication failed.", src_ip="10.0.0.1")
        high = make_alert(rule_level=10, rule_description="sshd: brute force trying to get access to the system.")
        incident = services.create_incident_from_alerts([low, high], user=self.user)
        self.assertEqual(incident.severity, "high")
        self.assertEqual(incident.status, S.NEW)
        self.assertEqual(incident.title, "sshd: brute force trying to get access to the system from 192.168.56.1")
        self.assertEqual(incident.assigned_to, self.user)
        self.assertEqual(incident.alerts.count(), 2)
        for alert in (low, high):
            alert.refresh_from_db()
            self.assertEqual(alert.status, Alert.Status.INVESTIGATING)
        self.assertEqual(incident.notes.count(), 1)  # audit entry for creation

    def test_custom_title(self):
        incident = services.create_incident_from_alerts([make_alert()], user=self.user, title="  My title ")
        self.assertEqual(incident.title, "My title")

    def test_title_without_source_ip(self):
        incident = services.create_incident_from_alerts(
            [make_alert(src_ip=None, rule_description="Integrity checksum changed.")], user=self.user
        )
        self.assertEqual(incident.title, "Integrity checksum changed")

    def test_requires_alerts(self):
        with self.assertRaises(WorkflowError):
            services.create_incident_from_alerts([], user=self.user)

    def test_rejects_already_triaged_alerts(self):
        with self.assertRaises(WorkflowError):
            services.create_incident_from_alerts([make_alert(status=Alert.Status.CLOSED)], user=self.user)
        self.assertEqual(Incident.objects.count(), 0)

    def test_display_id(self):
        incident = services.create_incident_from_alerts([make_alert()], user=self.user)
        self.assertEqual(incident.display_id, f"INC-{incident.pk:03d}")


class TransitionTests(TestCase):
    def setUp(self):
        self.user = make_user("analyst1")

    def test_every_transition_allowed_or_rejected(self):
        for start in S:
            for target in ACTIONS:
                with self.subTest(start=start, target=target):
                    incident = make_incident(status=start)
                    if target in ALLOWED[start]:
                        ACTIONS[target](incident, self.user)
                        incident.refresh_from_db()
                        self.assertEqual(incident.status, target)
                    else:
                        with self.assertRaises(WorkflowError):
                            ACTIONS[target](incident, self.user)
                        incident.refresh_from_db()
                        self.assertEqual(incident.status, start)

    def test_false_positive_allowed_from_open_states_only(self):
        for start in S:
            with self.subTest(start=start):
                incident = make_incident(status=start)
                if start == S.CLOSED:
                    with self.assertRaises(WorkflowError):
                        services.mark_false_positive(incident, user=self.user, reason="planned")
                else:
                    services.mark_false_positive(incident, user=self.user, reason="planned")
                    incident.refresh_from_db()
                    self.assertEqual(incident.status, S.CLOSED)


class ReasonRuleTests(TestCase):
    def setUp(self):
        self.user = make_user("analyst1")
        self.incident = make_incident(status=S.INVESTIGATING)

    def test_close_requires_reason(self):
        for reason in ("", "   ", None):
            with self.subTest(reason=reason), self.assertRaises(WorkflowError):
                services.close(self.incident, user=self.user, reason=reason)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, S.INVESTIGATING)
        self.assertEqual(self.incident.notes.count(), 0)

    def test_false_positive_requires_reason(self):
        with self.assertRaises(WorkflowError):
            services.mark_false_positive(self.incident, user=self.user, reason=" ")
        self.incident.refresh_from_db()
        self.assertFalse(self.incident.is_false_positive)

    def test_escalation_requires_target_and_reason(self):
        with self.assertRaises(WorkflowError):
            services.escalate(self.incident, user=self.user, target="", reason="why")
        with self.assertRaises(WorkflowError):
            services.escalate(self.incident, user=self.user, target="L9", reason="why")
        with self.assertRaises(WorkflowError):
            services.escalate(self.incident, user=self.user, target="L2", reason="")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, S.INVESTIGATING)

    def test_empty_note_rejected(self):
        with self.assertRaises(WorkflowError):
            services.add_note(self.incident, user=self.user, text="  ")


class AuditTrailAndAlertStatusTests(TestCase):
    def setUp(self):
        self.user = make_user("analyst1")
        self.alerts = [make_alert(), make_alert()]
        self.incident = services.create_incident_from_alerts(self.alerts, user=self.user)

    def statuses(self):
        return {Alert.objects.get(pk=a.pk).status for a in self.alerts}

    def kinds(self):
        return list(self.incident.notes.values_list("kind", flat=True))

    def test_escalation(self):
        services.escalate(self.incident, user=self.user, target="L2", reason="Possible compromise")
        self.incident.refresh_from_db()
        self.assertEqual((self.incident.status, self.incident.escalated_to), (S.ESCALATED, "L2"))
        self.assertEqual(self.statuses(), {Alert.Status.INVESTIGATING})
        note = self.incident.notes.last()
        self.assertEqual(note.kind, IncidentNote.Kind.ESCALATION)
        self.assertIn("Possible compromise", note.text)

    def test_close_and_reopen(self):
        services.close(self.incident, user=self.user, reason="Benign")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, S.CLOSED)
        self.assertIsNotNone(self.incident.closed_at)
        self.assertEqual(self.statuses(), {Alert.Status.CLOSED})
        self.assertEqual(self.incident.notes.last().kind, IncidentNote.Kind.STATUS_CHANGE)

        services.start_investigating(self.incident, user=self.user, reason="New evidence")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, S.INVESTIGATING)
        self.assertIsNone(self.incident.closed_at)
        self.assertEqual(self.statuses(), {Alert.Status.INVESTIGATING})

    def test_false_positive(self):
        services.mark_false_positive(self.incident, user=self.user, reason="Planned change")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, S.CLOSED)
        self.assertTrue(self.incident.is_false_positive)
        self.assertIsNotNone(self.incident.closed_at)
        self.assertEqual(self.statuses(), {Alert.Status.FALSE_POSITIVE})
        self.assertEqual(self.incident.notes.last().kind, IncidentNote.Kind.FALSE_POSITIVE)

    def test_reopening_a_false_positive_clears_the_flag(self):
        services.mark_false_positive(self.incident, user=self.user, reason="Planned change")
        services.start_investigating(self.incident, user=self.user)
        self.incident.refresh_from_db()
        self.assertFalse(self.incident.is_false_positive)

    def test_full_path_leaves_complete_audit_trail(self):
        services.start_investigating(self.incident, user=self.user)
        services.add_note(self.incident, user=self.user, text="Checked auth.log")
        services.escalate(self.incident, user=self.user, target="L2", reason="Needs review")
        services.start_investigating(self.incident, user=self.user)
        services.close(self.incident, user=self.user, reason="No impact")
        self.assertEqual(
            self.kinds(),
            ["status_change", "status_change", "note", "escalation", "status_change", "status_change"],
        )

    def test_update_details_logs_severity_and_assignment_changes(self):
        other = make_user("bob")
        services.update_details(
            self.incident,
            user=self.user,
            title="Renamed",
            severity="critical",
            assigned_to=other,
            recommended_actions=" one \n\n two ",
        )
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.severity, "critical")
        self.assertEqual(self.incident.recommended_actions, "one\ntwo")
        texts = " ".join(self.incident.notes.values_list("text", flat=True))
        self.assertIn("Severity changed from High to Critical", texts)
        self.assertIn("Assigned to bob", texts)

    def test_update_details_validates(self):
        with self.assertRaises(WorkflowError):
            services.update_details(
                self.incident, user=self.user, title="", severity="high", assigned_to=None, recommended_actions=""
            )
        with self.assertRaises(WorkflowError):
            services.update_details(
                self.incident, user=self.user, title="x", severity="bogus", assigned_to=None, recommended_actions=""
            )
