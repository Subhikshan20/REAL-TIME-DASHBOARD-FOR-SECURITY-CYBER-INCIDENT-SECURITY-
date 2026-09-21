"""Shared pytest fixtures for the SOC dashboard test-suite."""

from __future__ import annotations

import gzip
import json
import os
import sys

import pytest

# Make the project modules importable when running `pytest` from the repo root.
# All application modules live under ``src/``.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))


@pytest.fixture(scope="session")
def _seeded_mock_dataset(tmp_path_factory):
    """
    Generate ONE deterministic mock dataset in a session temp dir. The whole
    suite points the ``mock`` source at this copy (see ``_isolate_runtime_state``)
    so no test ever reads — or regenerates — the project's real ``data/`` files.
    Seeded + non-random so results are reproducible run-to-run.
    """
    import mock_data_generator as mdg

    d = tmp_path_factory.mktemp("mockdata")
    mdg.generate(out_dir=str(d), seed=42, randomize=False)
    return str(d)


@pytest.fixture(autouse=True)
def _isolate_runtime_state(tmp_path_factory, monkeypatch, _seeded_mock_dataset):
    """
    Redirect all mutable runtime-state files AND the mock dataset to temp dirs so
    the test-suite (incl. AppTest, which runs the real app.py) never reads or
    writes the project's production ``data/`` artefacts (prefs, triage state,
    audit log, alert stream, ground truth). This makes every test hermetic and
    immune to the app's own "Reset data" action having emptied ``data/``.
    """
    import os

    import config

    d = tmp_path_factory.mktemp("state")
    monkeypatch.setattr(config.settings, "PREFS_FILE", str(d / "ui_prefs.json"))
    monkeypatch.setattr(config.settings, "INCIDENT_STATE_FILE", str(d / "incident_state.json"))
    monkeypatch.setattr(config.settings, "AUDIT_LOG_FILE", str(d / "audit.log"))

    # Point the mock dataset at the isolated seeded copy (never the real data/).
    ds = _seeded_mock_dataset
    monkeypatch.setattr(config.settings, "DATA_DIR", ds)
    monkeypatch.setattr(config.settings, "ALERTS_FILE", os.path.join(ds, "wazuh_alerts.json"))
    monkeypatch.setattr(config.settings, "GROUND_TRUTH_FILE", os.path.join(ds, "ground_truth.json"))
    monkeypatch.setattr(config.settings, "EVE_FILE", os.path.join(ds, "suricata_eve.json"))


@pytest.fixture
def suricata_alert_event():
    """A raw Suricata EVE `alert` event (as written to eve.json)."""
    return {
        "timestamp": "2026-06-27T10:15:30.123456+0000",
        "flow_id": 1234567890123,
        "event_type": "alert",
        "src_ip": "203.0.113.7",
        "src_port": 51514,
        "dest_ip": "10.0.0.5",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2001219,
            "rev": 1,
            "signature": "ET SCAN Potential SSH Scan",
            "category": "Attempted Information Leak",
            "severity": 2,
            "metadata": {"mitre_technique_id": ["T1046"], "mitre_tactic": ["Discovery"]},
        },
    }


@pytest.fixture
def suricata_flow_event():
    """A non-alert EVE event that must be ignored by the alert adapter."""
    return {"timestamp": "2026-06-27T10:15:31.000+0000", "event_type": "flow", "src_ip": "10.0.0.9"}


@pytest.fixture
def wazuh_bruteforce_alert():
    """A canonical Wazuh alert document for an SSH brute-force detection."""
    return {
        "timestamp": "2026-06-27T10:20:00.000+0000",
        "id": "1782000000.1",
        "agent": {"id": "002", "name": "web-server-01"},
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "sshd: Attempt to login using a non-existent user (admin)",
            "groups": ["syslog", "sshd", "authentication_failed", "brute_force"],
            "mitre": {
                "id": ["T1110"],
                "tactic": ["Credential Access"],
                "technique": ["Brute Force"],
            },
        },
        "location": "/var/log/auth.log",
        "decoder": {"name": "sshd"},
        "data": {"srcip": "45.155.205.99", "dstuser": "admin", "dstip": "10.0.0.5"},
        "validation": {"is_true_positive": True, "attack_type": "Brute Force"},
    }


@pytest.fixture
def metrics_gt():
    """Measured lab facts ONLY — no pre-stated detection results."""
    return {
        "campaigns": [
            {
                "attack_type": "Brute Force",
                "source_ip": "1.1.1.1",
                "start_time": "2026-06-27T10:00:00.000+0000",
                "end_time": "2026-06-27T10:10:00.000+0000",
                "malicious_attempts": 10,
            }
        ],
        "benign": {"benign_events": 100},
    }


@pytest.fixture
def metrics_df(metrics_gt):
    """
    A hand-built alert stream so every dynamic metric is verifiable:
      * 3 network alerts (src 1.1.1.1) at +5/+6/+7s  -> detected = 3, TP = 3
      * 1 host alert      (src 1.1.1.1) at +20s       -> host MTTD = 20s
      * 1 benign alert    (src 9.9.9.9) at +5min      -> false positive = 1
    With malicious_attempts=10 -> FN=7; benign_events=100 -> TN=99.
    """
    import data_processor as dp

    def net(ts):
        return {
            "timestamp": ts,
            "agent": {"name": "suricata-sensor"},
            "rule": {
                "id": "1",
                "level": 10,
                "description": "ET SCAN ssh bruteforce tool",
                "groups": ["ids", "suricata", "brute_force"],
                "mitre": {"id": ["T1110"], "tactic": [], "technique": []},
            },
            "decoder": {"name": "suricata"},
            "data": {
                "srcip": "1.1.1.1",
                "dest_ip": "2.2.2.2",
                "alert": {"signature": "ET SCAN ssh bruteforce tool", "category": "x"},
            },
        }

    def host(ts):
        return {
            "timestamp": ts,
            "agent": {"name": "web-server-01"},
            "rule": {
                "id": "5710",
                "level": 10,
                "description": "sshd authentication failure",
                "groups": ["sshd", "brute_force"],
                "mitre": {"id": ["T1110"], "tactic": [], "technique": []},
            },
            "decoder": {"name": "sshd"},
            "data": {"srcip": "1.1.1.1", "dstip": "2.2.2.2"},
        }

    def fp(ts):
        return {
            "timestamp": ts,
            "agent": {"name": "suricata-sensor"},
            "rule": {
                "id": "31530",
                "level": 3,
                "description": "ET POLICY benign curl UA",
                "groups": ["ids", "suricata", "policy"],
                "mitre": {"id": [], "tactic": [], "technique": []},
            },
            "decoder": {"name": "suricata"},
            "data": {
                "srcip": "9.9.9.9",
                "dest_ip": "3.3.3.3",
                "alert": {
                    "signature": "ET POLICY benign curl UA",
                    "category": "Not Suspicious Traffic",
                },
            },
        }

    alerts = [
        net("2026-06-27T10:00:05.000+0000"),
        net("2026-06-27T10:00:06.000+0000"),
        net("2026-06-27T10:00:07.000+0000"),
        host("2026-06-27T10:00:20.000+0000"),
        fp("2026-06-27T10:05:00.000+0000"),
    ]
    return dp.normalize_alerts(alerts)


@pytest.fixture
def eve_file(tmp_path, suricata_alert_event, suricata_flow_event):
    """Write a small eve.json (NDJSON) with two DISTINCT alerts, a flow, and junk."""
    second = dict(suricata_alert_event)  # a genuinely distinct second alert
    second["flow_id"] = suricata_alert_event["flow_id"] + 1
    second["timestamp"] = "2026-06-27T10:15:31.500000+0000"
    path = tmp_path / "eve.json"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(suricata_alert_event) + "\n")
        fh.write(json.dumps(suricata_flow_event) + "\n")
        fh.write("this-is-not-json\n")  # malformed -> must be skipped
        fh.write(json.dumps(second) + "\n")
    return str(path)


@pytest.fixture
def eve_file_gz(tmp_path, suricata_alert_event):
    """Write a gzipped eve.json.gz with a single alert."""
    path = tmp_path / "eve.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write(json.dumps(suricata_alert_event) + "\n")
    return str(path)


@pytest.fixture
def wazuh_export_array(tmp_path, wazuh_bruteforce_alert):
    """Wazuh export as a JSON array."""
    path = tmp_path / "alerts_array.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([wazuh_bruteforce_alert, wazuh_bruteforce_alert], fh)
    return str(path)


@pytest.fixture
def wazuh_export_ndjson(tmp_path, wazuh_bruteforce_alert):
    """Wazuh export as NDJSON."""
    path = tmp_path / "alerts_nd.json"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(wazuh_bruteforce_alert) + "\n")
        fh.write(json.dumps(wazuh_bruteforce_alert) + "\n")
    return str(path)
