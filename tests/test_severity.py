from django.test import SimpleTestCase, TestCase

from alerts.models import Alert
from alerts.severity import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    describe_mapping,
    highest_severity,
    severity_filter,
    severity_for_level,
)

from .helpers import make_alert


class SeverityMappingTests(SimpleTestCase):
    def test_boundaries(self):
        cases = {0: LOW, 6: LOW, 7: MEDIUM, 9: MEDIUM, 10: HIGH, 12: HIGH, 13: CRITICAL, 15: CRITICAL}
        for level, expected in cases.items():
            with self.subTest(level=level):
                self.assertEqual(severity_for_level(level), expected)

    def test_missing_level_is_low(self):
        self.assertEqual(severity_for_level(None), LOW)

    def test_highest_severity(self):
        self.assertEqual(highest_severity([LOW, HIGH, MEDIUM]), HIGH)
        self.assertEqual(highest_severity([]), LOW)

    def test_description_matches_footnote(self):
        self.assertEqual(describe_mapping(), "level 0-6 Low, 7-9 Medium, 10-12 High, 13+ Critical")


class SeverityFilterTests(TestCase):
    def test_filter_agrees_with_function(self):
        for level in (None, 0, 6, 7, 9, 10, 12, 13, 15):
            make_alert(rule_level=level)
        for severity in (LOW, MEDIUM, HIGH, CRITICAL):
            with self.subTest(severity=severity):
                from_db = {a.pk for a in Alert.objects.filter(severity_filter(severity))}
                expected = {a.pk for a in Alert.objects.all() if a.severity == severity}
                self.assertEqual(from_db, expected)
