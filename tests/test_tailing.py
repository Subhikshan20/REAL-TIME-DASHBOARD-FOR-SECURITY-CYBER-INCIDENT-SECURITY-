"""Tests for incremental eve.json tailing (ingest.tail_suricata_eve)."""

import json

import pytest

import ingest


def _write_events(path, events, mode="w"):
    with open(path, mode, encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")


def test_tail_reads_then_only_new(tmp_path, suricata_alert_event):
    path = str(tmp_path / "eve.json")
    _write_events(path, [suricata_alert_event, suricata_alert_event])

    alerts, state = ingest.tail_suricata_eve(path, None)
    assert len(alerts) == 2
    assert state["offset"] > 0

    # No new data -> nothing returned, offset unchanged.
    alerts2, state2 = ingest.tail_suricata_eve(path, state)
    assert alerts2 == []
    assert state2["offset"] == state["offset"]

    # Append one more event -> only that one is read.
    _write_events(path, [suricata_alert_event], mode="a")
    alerts3, state3 = ingest.tail_suricata_eve(path, state2)
    assert len(alerts3) == 1
    assert state3["offset"] > state2["offset"]


def test_tail_handles_rotation(tmp_path, suricata_alert_event):
    path = str(tmp_path / "eve.json")
    _write_events(path, [suricata_alert_event, suricata_alert_event])
    _, state = ingest.tail_suricata_eve(path, None)

    # Truncate / rotate: rewrite a smaller file.
    _write_events(path, [suricata_alert_event])
    alerts, new_state = ingest.tail_suricata_eve(path, state)
    assert len(alerts) == 1  # re-read from the start
    assert new_state["offset"] <= state["offset"]


def test_tail_skips_non_alert_events(tmp_path, suricata_alert_event, suricata_flow_event):
    path = str(tmp_path / "eve.json")
    _write_events(path, [suricata_flow_event, suricata_alert_event, suricata_flow_event])
    alerts, _ = ingest.tail_suricata_eve(path, None)
    assert len(alerts) == 1


def test_tail_rejects_gzip(tmp_path):
    with pytest.raises(ingest.IngestError):
        ingest.tail_suricata_eve(str(tmp_path / "eve.json.gz"), None)


def test_tail_missing_file_raises():
    with pytest.raises(ingest.IngestError):
        ingest.tail_suricata_eve("/no/such/eve.json", None)
