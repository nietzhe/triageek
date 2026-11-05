import json
import os
import tempfile
from datetime import timezone
from io import StringIO
from pathlib import Path

from django.core.management import CommandError, call_command
from django.test import SimpleTestCase, TestCase

from alerts.ingest import (
    IngestError,
    InvalidAlertLine,
    ingest_file,
    parse_alert_line,
    parse_timestamp,
)
from alerts.models import Alert, IngestState

from .helpers import utc, wazuh_line


class ParseTimestampTests(SimpleTestCase):
    def test_fractional(self):
        self.assertEqual(parse_timestamp("2026-11-04T12:41:07.123+0000"), utc(hour=12, minute=41, second=7).replace(microsecond=123000))

    def test_without_fraction(self):
        self.assertEqual(parse_timestamp("2026-11-04T12:41:07+0000"), utc(hour=12, minute=41, second=7))

    def test_other_offset_is_converted_to_utc(self):
        parsed = parse_timestamp("2026-11-04T19:41:07.000+0700")
        self.assertEqual(parsed, utc(hour=12, minute=41, second=7))
        self.assertEqual(parsed.tzinfo, timezone.utc)

    def test_garbage_raises(self):
        for value in (None, "", "yesterday"):
            with self.subTest(value=value), self.assertRaises(InvalidAlertLine):
                parse_timestamp(value)


class ParseLineTests(SimpleTestCase):
    def test_valid_line(self):
        alert = parse_alert_line(wazuh_line())
        self.assertEqual(alert.wazuh_id, "1762260067.12345")
        self.assertEqual(alert.agent_name, "ubuntu-server")
        self.assertEqual(alert.rule_id, "5763")
        self.assertEqual(alert.rule_level, 10)
        self.assertEqual(alert.src_ip, "192.168.56.1")
        self.assertIn("sshd", alert.full_log)
        self.assertEqual(alert.raw["agent"]["id"], "001")  # whole object kept

    def test_missing_srcip_is_null(self):
        self.assertIsNone(parse_alert_line(wazuh_line(data=None)).src_ip)
        self.assertIsNone(parse_alert_line(wazuh_line(data={"other": "x"})).src_ip)

    def test_src_ip_fallback(self):
        alert = parse_alert_line(wazuh_line(data={"src_ip": "10.0.0.9"}))
        self.assertEqual(alert.src_ip, "10.0.0.9")

    def test_absent_fields_are_empty_not_invented(self):
        alert = parse_alert_line(wazuh_line(rule=None, agent=None, full_log=None))
        self.assertIsNone(alert.rule_level)
        self.assertEqual(alert.rule_id, "")
        self.assertEqual(alert.agent_name, "")
        self.assertEqual(alert.full_log, "")

    def test_invalid_lines(self):
        for line in ("{not json", "[1, 2]", "{}", wazuh_line(id=None), wazuh_line(timestamp="nope")):
            with self.subTest(line=line), self.assertRaises(InvalidAlertLine):
                parse_alert_line(line)


class IngestFileTests(TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "alerts.json"

    def write(self, *lines, mode="w"):
        with open(self.path, mode, encoding="utf-8") as handle:
            for line in lines:
                handle.write(line + "\n")

    def lines(self, count, start=0):
        return [wazuh_line(id=f"id-{i}") for i in range(start, start + count)]

    def test_ingests_all_valid_lines(self):
        self.write(*self.lines(3))
        result = ingest_file(self.path)
        self.assertEqual(result.created, 3)
        self.assertEqual(Alert.objects.count(), 3)
        self.assertEqual(IngestState.objects.get().offset, os.path.getsize(self.path))

    def test_malformed_line_is_skipped(self):
        self.write(wazuh_line(id="a"), "{broken json", wazuh_line(id="b"))
        with self.assertLogs("alerts.ingest", level="WARNING"):
            result = ingest_file(self.path)
        self.assertEqual(result.created, 2)
        self.assertEqual(result.malformed, 1)

    def test_reingest_creates_no_duplicates(self):
        self.write(*self.lines(3))
        ingest_file(self.path)
        again = ingest_file(self.path)
        self.assertEqual(again.created, 0)
        self.assertEqual(Alert.objects.count(), 3)

    def test_duplicates_are_skipped_even_when_offset_is_lost(self):
        self.write(*self.lines(3))
        ingest_file(self.path)
        IngestState.objects.all().delete()
        result = ingest_file(self.path)
        self.assertEqual(result.created, 0)
        self.assertEqual(result.duplicates, 3)
        self.assertEqual(Alert.objects.count(), 3)

    def test_resumes_from_offset(self):
        self.write(*self.lines(2))
        ingest_file(self.path)
        self.write(*self.lines(2, start=2), mode="a")
        result = ingest_file(self.path)
        self.assertEqual(result.lines_read, 2)  # only the new lines were read
        self.assertEqual(result.created, 2)
        self.assertEqual(Alert.objects.count(), 4)

    def test_truncated_file_restarts_from_zero(self):
        self.write(*self.lines(3))
        ingest_file(self.path)
        self.write(wazuh_line(id="fresh"))  # same inode, smaller than stored offset
        result = ingest_file(self.path)
        self.assertTrue(result.restarted)
        self.assertEqual(result.created, 1)
        self.assertTrue(Alert.objects.filter(wazuh_id="fresh").exists())

    def test_new_inode_restarts_from_zero_even_if_bigger(self):
        self.write(wazuh_line(id="old"))
        ingest_file(self.path)
        os.rename(self.path, self.path.with_name("alerts.json.1"))
        self.write(*[wazuh_line(id=f"new-{i}") for i in range(5)])  # new file, new inode, larger
        result = ingest_file(self.path)
        self.assertTrue(result.restarted)
        self.assertEqual(result.created, 5)
        self.assertEqual(IngestState.objects.get().offset, os.path.getsize(self.path))

    def test_partial_trailing_line_waits_for_the_rest(self):
        complete = wazuh_line(id="complete")
        partial = wazuh_line(id="partial")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(complete + "\n" + partial[:20])
        result = ingest_file(self.path)
        self.assertEqual(result.created, 1)
        self.assertEqual(result.malformed, 0)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(partial[20:] + "\n")
        result = ingest_file(self.path)
        self.assertEqual(result.created, 1)
        self.assertEqual(Alert.objects.count(), 2)

    def test_last_line_without_newline_is_ingested_when_complete(self):
        self.path.write_text(wazuh_line(id="no-newline"), encoding="utf-8")
        self.assertEqual(ingest_file(self.path).created, 1)

    def test_batches(self):
        self.write(*self.lines(7))
        result = ingest_file(self.path, batch_size=3)
        self.assertEqual(result.created, 7)

    def test_missing_file(self):
        with self.assertRaises(IngestError) as ctx:
            ingest_file(self.path)
        self.assertIn("not found", str(ctx.exception))

    def test_unreadable_file_message_mentions_wazuh_group(self):
        self.write(*self.lines(1))
        os.chmod(self.path, 0o000)
        self.addCleanup(os.chmod, self.path, 0o600)
        if os.access(self.path, os.R_OK):
            self.skipTest("running as a user that ignores file permissions")
        with self.assertRaises(IngestError) as ctx:
            ingest_file(self.path)
        message = str(ctx.exception)
        self.assertIn("wazuh", message)
        self.assertIn("Do not run Django as root", message)

    def test_raw_keeps_original_object(self):
        self.write(wazuh_line(id="raw-1"))
        ingest_file(self.path)
        raw = Alert.objects.get(wazuh_id="raw-1").raw
        self.assertEqual(raw["rule"]["id"], "5763")
        self.assertEqual(json.loads(wazuh_line(id="raw-1")), raw)


class IngestCommandTests(TestCase):
    def test_command_reports_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.json"
            path.write_text(wazuh_line(id="x1") + "\n" + wazuh_line(id="x2") + "\n", encoding="utf-8")
            out = StringIO()
            call_command("ingest_alerts", path=str(path), stdout=out)
            call_command("ingest_alerts", path=str(path), stdout=out)
            self.assertIn("2 new alert(s)", out.getvalue())
            self.assertEqual(Alert.objects.count(), 2)

    def test_command_missing_file_is_a_clear_error(self):
        with self.assertRaisesMessage(CommandError, "not found"):
            call_command("ingest_alerts", path="/nonexistent/alerts.json")
