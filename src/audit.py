"""
audit.py
========
Append-only audit log of security-relevant dashboard actions (logins, data
exports, triage changes, notifications). Each entry is one JSON line with a
UTC timestamp, so the record is tamper-evident-ish and easy to ship to a SIEM.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from config import settings
from logging_config import get_logger

log = get_logger("audit")


def record(event: str, user: str = "anonymous", detail: str = "", path: str | None = None) -> None:
    """Append one audit entry. Never raises (auditing must not break the app)."""
    path = path or settings.AUDIT_LOG_FILE
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "user": user,
        "detail": detail,
    }
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError as exc:  # pragma: no cover - disk issues shouldn't crash the UI
        log.warning("Could not write audit entry: %s", exc)


def read_audit(limit: int = 200, path: str | None = None) -> list[dict[str, Any]]:
    """Return the most recent audit entries (newest first)."""
    path = path or settings.AUDIT_LOG_FILE
    if not os.path.exists(path):
        return []
    out: list[dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return list(reversed(out))[:limit]
