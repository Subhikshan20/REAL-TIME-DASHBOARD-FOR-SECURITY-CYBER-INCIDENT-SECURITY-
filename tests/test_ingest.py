"""Tests for the ingestion layer (ingest.py)."""

import os

import pytest

import ingest


# --------------------------------------------------------------------------- #
# Suricata EVE -> canonical mapping
# --------------------------------------------------------------------------- #
def test_suricata_event_maps_core_fields(suricata_alert_event):
    alert = ingest.suricata_event_to_alert(suricata_alert_event)
    assert alert is not None
    assert alert["data"]["srcip"] == "203.0.113.7"
    assert alert["data"]["dest_ip"] == "10.0.0.5"
    assert alert["data"]["dest_port"] == "22"
    assert alert["rule"]["description"] == "ET SCAN Potential SSH Scan"
    # ATT&CK metadata carried by the rule must be preserved verbatim.
    assert alert["rule"]["mitre"]["id"] == ["T1046"]
    assert alert["decoder"]["name"] == "suricata"


def test_suricata_severity_mapped_to_level(suricata_alert_event):
    # severity 2 (medium) -> Wazuh level 8
    alert = ingest.suricata_event_to_alert(suricata_alert_event)
    assert alert["rule"]["level"] == 8


def test_non_alert_event_is_ignored(suricata_flow_event):
    assert ingest.suricata_event_to_alert(suricata_flow_event) is None


# --------------------------------------------------------------------------- #
# File readers
# --------------------------------------------------------------------------- #
def test_read_suricata_eve_skips_flow_and_malformed(eve_file):
    alerts = ingest.read_suricata_eve(eve_file)
    # File had 2 alert events, 1 flow event, 1 junk line -> 2 alerts.
    assert len(alerts) == 2
    assert all(a["decoder"]["name"] == "suricata" for a in alerts)


def test_read_suricata_eve_gzip(eve_file_gz):
    alerts = ingest.read_suricata_eve(eve_file_gz)
    assert len(alerts) == 1


def test_read_suricata_eve_missing_file_raises():
    with pytest.raises(ingest.IngestError):
        ingest.read_suricata_eve("/no/such/eve.json")


def test_read_wazuh_export_array(wazuh_export_array):
    alerts = ingest.read_wazuh_export(wazuh_export_array)
    assert len(alerts) == 2
    assert alerts[0]["rule"]["id"] == "5710"


def test_read_wazuh_export_ndjson(wazuh_export_ndjson):
    alerts = ingest.read_wazuh_export(wazuh_export_ndjson)
    assert len(alerts) == 2


# --------------------------------------------------------------------------- #
# Dispatcher + ground truth
# --------------------------------------------------------------------------- #
def test_load_alerts_unknown_source_raises():
    with pytest.raises(ingest.IngestError):
        ingest.load_alerts("not_a_source")


def test_load_alerts_dispatches_to_eve(eve_file):
    alerts = ingest.load_alerts("suricata_eve", path=eve_file)
    assert len(alerts) == 2


def test_load_ground_truth_missing_returns_empty():
    assert ingest.load_ground_truth("/no/such/ground_truth.json") == {}


# --------------------------------------------------------------------------- #
# Browser uploads
# --------------------------------------------------------------------------- #
def test_save_uploaded_file_roundtrips_through_readers(tmp_path, suricata_alert_event):
    """An uploaded eve.json is persisted and then read back via the normal reader."""
    import json

    payload = (json.dumps(suricata_alert_event) + "\n").encode("utf-8")
    path = ingest.save_uploaded_file(payload, "eve.json", dest_dir=str(tmp_path))
    assert path.endswith("eve.json")
    alerts = ingest.read_suricata_eve(path)
    assert len(alerts) == 1
    assert alerts[0]["data"]["srcip"] == "203.0.113.7"


def test_save_uploaded_file_sanitises_path_traversal(tmp_path):
    path = ingest.save_uploaded_file(b"[]", "../../evil.json", dest_dir=str(tmp_path))
    # The file must land inside dest_dir, not escape it.
    assert os.path.dirname(os.path.abspath(path)) == os.path.abspath(str(tmp_path))
    assert os.path.basename(path) == "evil.json"
