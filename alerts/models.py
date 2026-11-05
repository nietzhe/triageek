from django.db import models

from .severity import severity_for_level, severity_label


class Alert(models.Model):
    class Status(models.TextChoices):
        NEW = "new", "New"
        INVESTIGATING = "investigating", "Investigating"
        CLOSED = "closed", "Closed"
        FALSE_POSITIVE = "false_positive", "False positive"

    wazuh_id = models.CharField(max_length=64, unique=True)
    timestamp = models.DateTimeField(help_text="UTC")
    agent_name = models.CharField(max_length=128, blank=True)
    rule_id = models.CharField(max_length=32, blank=True)
    rule_level = models.PositiveSmallIntegerField(null=True, blank=True)
    rule_description = models.TextField(blank=True)
    src_ip = models.CharField(max_length=64, null=True, blank=True)
    full_log = models.TextField(blank=True)
    raw = models.JSONField(default=dict)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.NEW)
    is_demo = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp", "-pk"]
        indexes = [
            models.Index(fields=["-timestamp"], name="alert_timestamp_idx"),
            models.Index(fields=["rule_id"], name="alert_rule_id_idx"),
            models.Index(fields=["agent_name"], name="alert_agent_idx"),
            models.Index(fields=["src_ip"], name="alert_src_ip_idx"),
            models.Index(fields=["status"], name="alert_status_idx"),
            models.Index(fields=["is_demo"], name="alert_is_demo_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.wazuh_id} rule {self.rule_id or '?'} (level {self.rule_level})"

    @property
    def severity(self) -> str:
        return severity_for_level(self.rule_level)

    @property
    def severity_label(self) -> str:
        return severity_label(self.severity)


class IngestState(models.Model):
    path = models.CharField(max_length=1024, unique=True)
    inode = models.PositiveBigIntegerField(null=True, blank=True)
    offset = models.PositiveBigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.path} @ {self.offset}"
