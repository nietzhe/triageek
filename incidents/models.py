from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone

from alerts.severity import SEVERITY_CHOICES, SEVERITY_LABELS, severity_label


class Incident(models.Model):
    class Status(models.TextChoices):
        NEW = "new", "New"
        INVESTIGATING = "investigating", "Investigating"
        ESCALATED = "escalated", "Escalated"
        CLOSED = "closed", "Closed"

    title = models.CharField(max_length=200)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.NEW)
    is_false_positive = models.BooleanField(default=False)
    escalated_to = models.CharField(max_length=16, blank=True)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_incidents",
    )
    recommended_actions = models.TextField(blank=True, help_text="One action per line.")
    alerts = models.ManyToManyField("alerts.Alert", related_name="incidents", blank=True)
    # default=now (instead of auto_now_add) so demo data can be back-dated.
    created_at = models.DateTimeField(default=timezone.now)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
        indexes = [
            models.Index(fields=["status"], name="incident_status_idx"),
            models.Index(fields=["created_at"], name="incident_created_idx"),
            models.Index(fields=["closed_at"], name="incident_closed_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.display_id} {self.title}"

    def get_absolute_url(self) -> str:
        return reverse("incidents:detail", args=[self.pk])

    @property
    def display_id(self) -> str:
        return f"INC-{self.pk:03d}" if self.pk else "INC-new"

    @property
    def severity_label(self) -> str:
        return severity_label(self.severity) if self.severity in SEVERITY_LABELS else self.severity

    @property
    def status_label(self) -> str:
        if self.status == self.Status.CLOSED and self.is_false_positive:
            return "Closed (false positive)"
        return self.get_status_display()

    @property
    def is_open(self) -> bool:
        return self.status != self.Status.CLOSED

    @property
    def recommended_action_list(self) -> list[str]:
        return [line.strip() for line in self.recommended_actions.splitlines() if line.strip()]


class IncidentNote(models.Model):
    class Kind(models.TextChoices):
        NOTE = "note", "Note"
        STATUS_CHANGE = "status_change", "Status change"
        ESCALATION = "escalation", "Escalation"
        FALSE_POSITIVE = "false_positive", "False positive"

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="notes")
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="incident_notes"
    )
    text = models.TextField()
    kind = models.CharField(max_length=16, choices=Kind.choices, default=Kind.NOTE)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["created_at", "pk"]
        indexes = [models.Index(fields=["incident", "created_at"], name="note_incident_time_idx")]

    def __str__(self) -> str:
        return f"{self.incident.display_id} {self.kind} by {self.author}"
