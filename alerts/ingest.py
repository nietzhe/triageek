"""Read Wazuh 4.x ``alerts.json`` (one JSON object per line) into the database.

Design notes
------------
* Resumable: the byte offset and inode of the file are stored in ``IngestState``.
  A different inode or a file smaller than the stored offset means the log was
  rotated/truncated, so we restart from 0.
* Idempotent: ``Alert.wazuh_id`` is unique and already-known ids are skipped.
* Tolerant: malformed lines are logged and skipped, never fatal.
* A trailing line without a newline may still be mid-write by Wazuh, so it is only
  consumed if it already parses as a complete JSON object.
* Offsets are committed in the same transaction as each batch of alerts, which
  keeps writes few (HDD friendly) and the state consistent.
"""

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from django.db import transaction

from .models import Alert, IngestState

logger = logging.getLogger("alerts.ingest")

DEFAULT_BATCH_SIZE = 500  # stays below SQLite's historical 999 bound-variable limit


class IngestError(Exception):
    """The alerts file cannot be read at all (as opposed to one bad line)."""


class InvalidAlertLine(ValueError):
    """One line could not be turned into an alert."""


@dataclass
class IngestResult:
    lines_read: int = 0
    created: int = 0
    duplicates: int = 0
    malformed: int = 0
    restarted: bool = False
    offset: int = 0


def parse_timestamp(value: Any) -> datetime:
    """Parse e.g. ``2026-11-04T12:41:07.123+0000`` (fraction optional) to aware UTC."""
    if not isinstance(value, str) or not value.strip():
        raise InvalidAlertLine("missing timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError as exc:
        raise InvalidAlertLine(f"unparseable timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        # Wazuh always writes an offset; if one is missing we assume UTC.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _optional_text(value: Any) -> str | None:
    text = _text(value).strip()
    return text or None


def _level(value: Any) -> int | None:
    try:
        level = int(value)
    except (TypeError, ValueError):
        return None
    return level if level >= 0 else None


def parse_alert_line(line: bytes | str) -> Alert:
    """Turn one ``alerts.json`` line into an unsaved ``Alert``.

    Only the fields below are mapped; nothing is invented. Absent fields become
    null/empty, and the complete object is kept in ``raw``.
    """
    try:
        obj = json.loads(line)
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidAlertLine("not valid JSON") from exc
    if not isinstance(obj, dict):
        raise InvalidAlertLine("JSON value is not an object")

    wazuh_id = _text(obj.get("id")).strip()
    if not wazuh_id:
        raise InvalidAlertLine("missing alert id")
    timestamp = parse_timestamp(obj.get("timestamp"))

    rule = _mapping(obj.get("rule"))
    agent = _mapping(obj.get("agent"))
    data = _mapping(obj.get("data"))

    # The source IP is not a top-level Wazuh field: decoders put it in ``data``,
    # usually as ``srcip``. Anything else stays available in ``raw``.
    src_ip = _optional_text(data.get("srcip")) or _optional_text(data.get("src_ip"))

    return Alert(
        wazuh_id=wazuh_id[:64],
        timestamp=timestamp,
        agent_name=_text(agent.get("name"))[:128],
        rule_id=_text(rule.get("id"))[:32],
        rule_level=_level(rule.get("level")),
        rule_description=_text(rule.get("description")),
        src_ip=src_ip[:64] if src_ip else None,
        full_log=obj.get("full_log") if isinstance(obj.get("full_log"), str) else "",
        raw=obj,
    )


def _permission_message(path: str) -> str:
    return (
        f"Cannot read '{path}': permission denied. This file is usually readable only by "
        "the 'wazuh' user and group, so the user that runs Django must be added to the "
        "'wazuh' group (for example `sudo usermod -aG wazuh <django-user>`, then log in "
        "again). Do not run Django as root."
    )


def _open_alerts_file(path: str):
    try:
        return open(path, "rb")
    except FileNotFoundError as exc:
        raise IngestError(
            f"Alerts file '{path}' was not found. Check --path or WAZUH_ALERTS_PATH, and "
            "that the Wazuh manager is running and has produced alerts."
        ) from exc
    except PermissionError as exc:
        raise IngestError(_permission_message(path)) from exc
    except OSError as exc:
        raise IngestError(f"Cannot open '{path}': {exc.strerror or exc}") from exc


def _flush(state: IngestState, batch: list[Alert], offset: int, inode: int, result: IngestResult):
    """Insert new alerts of ``batch`` and persist the offset atomically."""
    with transaction.atomic():
        if batch:
            known = set(
                Alert.objects.filter(wazuh_id__in=[a.wazuh_id for a in batch]).values_list(
                    "wazuh_id", flat=True
                )
            )
            fresh = []
            for alert in batch:
                if alert.wazuh_id in known:
                    result.duplicates += 1
                    continue
                known.add(alert.wazuh_id)
                fresh.append(alert)
            # ignore_conflicts is a second line of defence against a concurrent ingest.
            Alert.objects.bulk_create(fresh, ignore_conflicts=True)
            result.created += len(fresh)
        state.inode = inode
        state.offset = offset
        state.save(update_fields=["inode", "offset", "updated_at"])
    result.offset = offset


def ingest_file(path: str | os.PathLike, *, batch_size: int = DEFAULT_BATCH_SIZE) -> IngestResult:
    """Ingest new lines of ``path`` since the last run. Raises ``IngestError`` if unreadable."""
    path = os.fspath(path)
    result = IngestResult()

    with _open_alerts_file(path) as handle:
        stat = os.fstat(handle.fileno())
        state, _ = IngestState.objects.get_or_create(
            path=path, defaults={"inode": stat.st_ino, "offset": 0}
        )

        offset = state.offset
        rotated = state.inode is not None and state.inode != stat.st_ino
        if rotated or stat.st_size < offset:
            logger.info(
                "Alerts file %s was rotated or truncated (offset %s, size %s); restarting at 0.",
                path,
                offset,
                stat.st_size,
            )
            offset = 0
            result.restarted = True

        handle.seek(offset)
        position = offset
        batch: list[Alert] = []

        for raw_line in handle:
            complete = raw_line.endswith(b"\n")
            stripped = raw_line.strip()

            if not stripped:
                if not complete:
                    break
                position += len(raw_line)
                continue

            try:
                alert = parse_alert_line(stripped)
            except InvalidAlertLine as exc:
                if not complete:
                    # Possibly a half-written line; try again on the next run.
                    break
                result.lines_read += 1
                result.malformed += 1
                logger.warning(
                    "Skipping malformed line at byte %s of %s: %s", position, path, exc
                )
                position += len(raw_line)
                continue

            result.lines_read += 1
            position += len(raw_line)
            batch.append(alert)
            if len(batch) >= batch_size:
                _flush(state, batch, position, stat.st_ino, result)
                batch = []

        _flush(state, batch, position, stat.st_ino, result)

    return result
