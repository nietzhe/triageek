import logging
import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from alerts.ingest import IngestError, IngestResult, ingest_file

logger = logging.getLogger("alerts.ingest")


class Command(BaseCommand):
    help = "Ingest Wazuh 4.x alerts.json (one JSON object per line) into the database."

    def add_arguments(self, parser):
        parser.add_argument(
            "--path",
            default=None,
            help="Path to alerts.json (default: $WAZUH_ALERTS_PATH, then "
            "/var/ossec/logs/alerts/alerts.json).",
        )
        parser.add_argument(
            "--follow", action="store_true", help="Keep running and ingest new alerts as they arrive."
        )
        parser.add_argument(
            "--interval", type=float, default=5.0, help="Seconds between passes with --follow (default 5)."
        )

    def handle(self, *args, **options):
        path = options["path"] or settings.WAZUH_ALERTS_PATH
        follow = options["follow"]
        interval = options["interval"]
        if interval <= 0:
            raise CommandError("--interval must be greater than 0.")

        first_pass = True
        try:
            while True:
                try:
                    result = ingest_file(path)
                except IngestError as exc:
                    if first_pass or not follow:
                        raise CommandError(str(exc)) from exc
                    logger.error("%s (will retry in %ss)", exc, interval)
                else:
                    self._report(result, path, verbose=first_pass or not follow)
                first_pass = False
                if not follow:
                    return
                time.sleep(interval)
        except KeyboardInterrupt:
            self.stdout.write("Stopped.")

    def _report(self, result: IngestResult, path: str, *, verbose: bool) -> None:
        if not verbose and not (result.created or result.malformed or result.restarted):
            return  # stay quiet while following an idle file (HDD and log friendly)
        message = (
            f"{path}: {result.lines_read} line(s) read, {result.created} new alert(s), "
            f"{result.duplicates} duplicate(s), {result.malformed} malformed line(s) skipped."
        )
        if result.restarted:
            message += " File was rotated/truncated; restarted from the beginning."
        self.stdout.write(self.style.SUCCESS(message))
