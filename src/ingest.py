"""
ingest.py
=========
Unified ingestion layer. Every supported source is converted to a single
*canonical alert schema* (the Wazuh alert document), so the downstream
processing, classification, metrics and UI are identical regardless of origin.

Supported real-data sources
---------------------------
  * ``suricata_eve`` — a live Suricata ``eve.json`` file (newline-delimited
                       JSON, plain or gzipped). Raw EVE ``alert`` events are
                       wrapped into the canonical schema exactly the way Wazuh
                       wraps them on ingestion.
  * ``wazuh_export`` — an exported Wazuh alerts file (JSON array or NDJSON),
                       already in the canonical schema.
  * ``wazuh_api``    — the live Wazuh Indexer, via wazuh_api.WazuhClient.
  * ``mock``         — the labelled offline fixture (development only).

All file readers are defensive: missing files raise a clear error, and
individual malformed JSON records are skipped and counted rather than aborting
the whole ingest.
"""

from __future__ import annotations

import gzip
import io
import json
import os
from collections.abc import Iterable
from typing import Any

from config import settings
from logging_config import get_logger

log = get_logger("ingest")

# Sources that can be selected at runtime.
SOURCES = ("mock", "suricata_eve", "wazuh_export", "wazuh_api")


class IngestError(RuntimeError):
    """Raised when a source cannot be read or contains no usable records."""


# --------------------------------------------------------------------------- #
# Low-level file helpers
# --------------------------------------------------------------------------- #
def _open_text(path: str) -> io.TextIOBase:
    """Open a path for text reading, transparently handling gzip (.gz)."""
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def _iter_json_lines(path: str) -> Iterable[dict[str, Any]]:
    """
    Yield one parsed object per non-empty line of an NDJSON file.

    Malformed lines are logged and skipped so a single bad record never breaks
    a long real-world log file.
    """
    skipped = 0
    total = 0
    with _open_text(path) as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                if skipped <= 5:  # avoid log spam on heavily corrupt files
                    log.warning("Skipping malformed JSON at %s:%d", os.path.basename(path), lineno)
    if skipped:
        log.warning("%s: skipped %d/%d malformed records", os.path.basename(path), skipped, total)


def _load_json_any(path: str) -> list[dict[str, Any]]:
    """
    Load a file that is *either* a JSON array *or* NDJSON, returning a list.

    Wazuh exports come in both shapes depending on how they were produced
    (API dump vs. filebeat/logstash), so we auto-detect.
    """
    with _open_text(path) as fh:
        head = fh.read(2048)
    stripped = head.lstrip()
    if stripped.startswith("["):
        with _open_text(path) as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            raise IngestError(f"{path}: expected a JSON array of alerts.")
        return data
    # Otherwise treat as newline-delimited JSON.
    return list(_iter_json_lines(path))


# --------------------------------------------------------------------------- #
# Suricata EVE -> canonical Wazuh alert mapping
# --------------------------------------------------------------------------- #
def _suricata_severity_to_level(severity: Any) -> int:
    """Map Suricata alert severity (1 high .. 3/4 low) to a Wazuh rule level."""
    mapping = {1: 12, 2: 8, 3: 4, 4: 3}
    try:
        return mapping.get(int(severity), 5)
    except (TypeError, ValueError):
        return 5


def suricata_event_to_alert(eve: dict[str, Any]) -> dict[str, Any] | None:
    """
    Convert one raw Suricata EVE ``alert`` event into the canonical schema.

    Returns ``None`` for non-alert EVE events (flow, dns, http, stats, …) so
    callers can ingest a full eve.json and keep only the alerts.
    """
    if eve.get("event_type") != "alert":
        return None

    a = eve.get("alert", {}) or {}
    metadata = a.get("metadata", {}) or {}

    # ET/GPL rules frequently embed ATT&CK ids in rule metadata.
    mitre_ids = metadata.get("mitre_technique_id", []) or []
    mitre_tactics = metadata.get("mitre_tactic", []) or []
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]
    if isinstance(mitre_tactics, str):
        mitre_tactics = [mitre_tactics]

    category = a.get("category", "")
    groups = ["ids", "suricata"]
    if category:
        groups.append(category.lower().replace(" ", "_"))

    return {
        "timestamp": eve.get("timestamp"),
        "id": str(eve.get("flow_id", "")),
        "agent": {"name": "suricata-sensor"},
        "manager": {"name": "suricata"},
        "rule": {
            "id": str(a.get("signature_id", "")),
            "level": _suricata_severity_to_level(a.get("severity")),
            "description": a.get("signature", ""),
            "groups": groups,
            "mitre": {"id": list(mitre_ids), "tactic": list(mitre_tactics), "technique": []},
        },
        "location": "/var/log/suricata/eve.json",
        "decoder": {"name": "suricata"},
        "data": {
            "srcip": eve.get("src_ip"),
            "src_port": str(eve.get("src_port", "")),
            "dstip": eve.get("dest_ip"),
            "dest_ip": eve.get("dest_ip"),
            "dest_port": str(eve.get("dest_port", "")),
            "proto": eve.get("proto"),
            "flow_id": eve.get("flow_id"),
            "alert": {
                "action": a.get("action"),
                "gid": str(a.get("gid", "")),
                "signature_id": str(a.get("signature_id", "")),
                "rev": str(a.get("rev", "")),
                "signature": a.get("signature"),
                "category": category,
                "severity": str(a.get("severity", "")),
            },
        },
    }


# --------------------------------------------------------------------------- #
# Public readers
# --------------------------------------------------------------------------- #
def read_suricata_eve(path: str | None = None) -> list[dict[str, Any]]:
    """Read a real Suricata eve.json and return canonical alert documents."""
    path = path or settings.SURICATA_EVE_PATH
    if not path or not os.path.exists(path):
        raise IngestError(f"Suricata eve.json not found at: {path!r}")

    alerts: list[dict[str, Any]] = []
    for event in _iter_json_lines(path):
        alert = suricata_event_to_alert(event)
        if alert is not None:
            alerts.append(alert)
    log.info("Read %d Suricata alert events from %s", len(alerts), path)
    return alerts


def tail_suricata_eve(path: str | None = None, state: dict[str, Any] | None = None):
    """
    Incrementally read only the NEW alerts appended to a Suricata eve.json since
    the last call — the basis for real-time streaming without re-reading GBs.

    Args:
        path:  plain (non-gzip) eve.json path.
        state: {"offset": int, "size": int} returned by the previous call.

    Returns:
        (new_alerts, new_state). On detecting truncation/rotation (file smaller
        than last seen) the offset resets to 0 and the whole file is re-read.

    Note: byte-offset tailing reads complete lines only; a partial final line
    being written concurrently is skipped on this pass and picked up next time.
    """
    path = path or settings.SURICATA_EVE_PATH
    if path and path.endswith(".gz"):
        raise IngestError("Tailing is not supported for gzip files; use a plain eve.json.")
    if not path or not os.path.exists(path):
        raise IngestError(f"Suricata eve.json not found at: {path!r}")

    state = dict(state) if state else {"offset": 0, "size": 0}
    size = os.path.getsize(path)
    if size < state.get("size", 0):  # rotated or truncated -> start over
        log.info("eve.json rotation/truncation detected for %s; re-reading from start", path)
        state = {"offset": 0, "size": 0}

    alerts: list[dict[str, Any]] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        fh.seek(state.get("offset", 0))
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert = suricata_event_to_alert(event)
            if alert is not None:
                alerts.append(alert)
        new_offset = fh.tell()

    log.info("Tailed %d new Suricata alert(s) from %s", len(alerts), path)
    return alerts, {"offset": new_offset, "size": size}


def read_wazuh_export(path: str | None = None) -> list[dict[str, Any]]:
    """Read an exported Wazuh alerts file (JSON array or NDJSON)."""
    path = path or settings.WAZUH_EXPORT_PATH
    if not path or not os.path.exists(path):
        raise IngestError(f"Wazuh export not found at: {path!r}")
    alerts = _load_json_any(path)
    log.info("Read %d Wazuh alerts from export %s", len(alerts), path)
    return alerts


def save_uploaded_file(data: bytes, filename: str, dest_dir: str | None = None) -> str:
    """
    Persist a browser-uploaded file (eve.json / Wazuh export) to disk and return
    its path, so the normal path-based readers, mtime caching and time-windowing
    all keep working unchanged.

    The original extension is preserved (``.gz`` files stay gzipped and are
    transparently decompressed on read). The filename is sanitised to its base
    name to avoid any path traversal.
    """
    dest_dir = dest_dir or settings.UPLOAD_DIR
    os.makedirs(dest_dir, exist_ok=True)
    safe = os.path.basename(filename or "").strip() or "upload.json"
    path = os.path.join(dest_dir, safe)
    with open(path, "wb") as fh:
        fh.write(data)
    log.info("Saved uploaded file (%d bytes) to %s", len(data), path)
    return path


def read_mock_alerts(path: str | None = None) -> list[dict[str, Any]]:
    """Read the labelled offline mock dataset."""
    path = path or settings.ALERTS_FILE
    if not os.path.exists(path):
        return []
    return _load_json_any(path)


def fetch_wazuh_api(minutes: int = 240) -> list[dict[str, Any]]:
    """Pull alerts from the live Wazuh Indexer via the API client."""
    from wazuh_api import WazuhClient  # local import keeps requests optional offline

    return WazuhClient().fetch_alerts(minutes=minutes)


# --------------------------------------------------------------------------- #
# Dispatcher
# --------------------------------------------------------------------------- #
def load_alerts(
    source: str = "mock", *, path: str | None = None, minutes: int = 240
) -> list[dict[str, Any]]:
    """
    Load alerts from any supported source into the canonical schema.

    Args:
        source:  one of SOURCES.
        path:    file path override for the file-based sources.
        minutes: look-back window for the live API source.
    """
    if source not in SOURCES:
        raise IngestError(f"Unknown source {source!r}; expected one of {SOURCES}.")

    if source == "mock":
        return read_mock_alerts(path)
    if source == "suricata_eve":
        return read_suricata_eve(path)
    if source == "wazuh_export":
        return read_wazuh_export(path)
    if source == "wazuh_api":
        return fetch_wazuh_api(minutes=minutes)
    raise IngestError(f"Unhandled source {source!r}")  # pragma: no cover


def load_ground_truth(path: str | None = None) -> dict[str, Any]:
    """
    Load the labelled ground-truth ledger used for objective metrics.

    For mock data this is generated automatically. For real lab runs, populate a
    ground_truth.json describing each attack campaign you launched (see
    README §5) so accuracy / FPR / MTTD can be computed against known truth.
    """
    path = path or settings.GROUND_TRUTH_FILE
    if not os.path.exists(path):
        return {}
    try:
        with _open_text(path) as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Could not read ground truth %s: %s", path, exc)
        return {}
