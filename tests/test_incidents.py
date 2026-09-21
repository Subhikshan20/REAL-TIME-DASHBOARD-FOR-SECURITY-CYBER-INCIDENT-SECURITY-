"""Tests for incident grouping and triage persistence (incidents.py)."""

import data_processor as dp
import incidents


def _scan_alert(src, ts="2026-06-27T10:00:00.000+0000", alert_id=None):
    return {
        "timestamp": ts,
        "id": alert_id,
        "agent": {"name": "suricata-sensor"},
        "rule": {
            "id": "86601",
            "level": 8,
            "description": "ET SCAN Nmap",
            "groups": ["ids", "suricata", "recon"],
            "mitre": {"id": ["T1046"], "tactic": [], "technique": []},
        },
        "decoder": {"name": "suricata"},
        "data": {
            "srcip": src,
            "dest_ip": "10.0.0.5",
            "alert": {"signature": "ET SCAN Nmap", "category": "x"},
        },
    }


def test_incident_id_stable():
    a = incidents.incident_id("1.2.3.4", "Scan")
    b = incidents.incident_id("1.2.3.4", "Scan")
    c = incidents.incident_id("1.2.3.5", "Scan")
    assert a == b and a != c and len(a) == 10


def test_build_incidents_groups(wazuh_bruteforce_alert):
    df = dp.normalize_alerts(
        [
            _scan_alert("9.9.9.9", "2026-06-27T10:00:00.000+0000", "s1"),
            _scan_alert("9.9.9.9", "2026-06-27T10:01:00.000+0000", "s2"),
            wazuh_bruteforce_alert,
        ]
    )
    inc = incidents.build_incidents(df, states={})
    # Two distinct incidents: the scan (9.9.9.9) and the brute force (45.x).
    assert len(inc) == 2
    scan_row = inc[inc["attack_category"] == "Scan"].iloc[0]
    assert scan_row["alert_count"] == 2
    assert scan_row["status"] == "New"  # default when no saved state
    assert scan_row["layers"] == "network"


def test_build_incidents_applies_saved_state():
    df = dp.normalize_alerts([_scan_alert("9.9.9.9")])
    iid = incidents.incident_id("9.9.9.9", "Scan")
    states = {iid: {"status": "Resolved", "note": "benign scan from pentest"}}
    inc = incidents.build_incidents(df, states=states)
    assert inc.iloc[0]["status"] == "Resolved"
    assert "pentest" in inc.iloc[0]["note"]


def test_status_persistence_roundtrip(tmp_path):
    path = str(tmp_path / "state.json")
    incidents.set_status("abc123", "Investigating", "looking into it", path=path)
    states = incidents.load_states(path)
    assert states["abc123"]["status"] == "Investigating"
    assert states["abc123"]["note"] == "looking into it"
    assert "updated" in states["abc123"]


def test_set_status_rejects_unknown(tmp_path):
    import pytest

    with pytest.raises(ValueError):
        incidents.set_status("x", "Bogus", path=str(tmp_path / "s.json"))


def test_incident_member_alerts(wazuh_bruteforce_alert):
    df = dp.normalize_alerts([_scan_alert("9.9.9.9"), wazuh_bruteforce_alert])
    members = incidents.incident_member_alerts(df, "9.9.9.9", "Scan")
    assert len(members) == 1
    assert members.iloc[0]["src_ip"] == "9.9.9.9"
