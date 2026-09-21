"""Tests for normalisation, MITRE enrichment and aggregations (data_processor.py)."""

import pandas as pd

import data_processor as dp
import ingest


def test_normalize_empty_returns_columns():
    df = dp.normalize_alerts([])
    assert df.empty
    for col in ("attack_category", "mitre_ids", "mitre_source", "timestamp"):
        assert col in df.columns


def test_normalize_basic_fields(wazuh_bruteforce_alert):
    df = dp.normalize_alerts([wazuh_bruteforce_alert])
    assert len(df) == 1
    row = df.iloc[0]
    assert row["attack_category"] == "Brute Force"
    assert row["src_ip"] == "45.155.205.99"
    assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])


def test_mitre_source_rule_when_metadata_present(wazuh_bruteforce_alert):
    df = dp.normalize_alerts([wazuh_bruteforce_alert])
    assert df.iloc[0]["mitre_source"] == "rule"
    assert "T1110" in df.iloc[0]["mitre_ids"]


def test_mitre_source_inferred_when_absent():
    # A DoS signature with no ATT&CK metadata -> techniques inferred from category.
    alert = {
        "timestamp": "2026-06-27T10:00:00.000+0000",
        "rule": {
            "id": "1",
            "level": 12,
            "description": "ET DOS SYN Flood Inbound",
            "groups": ["dos"],
            "mitre": {"id": [], "tactic": [], "technique": []},
        },
        "data": {
            "alert": {
                "signature": "ET DOS SYN Flood Inbound",
                "category": "Attempted Denial of Service",
            }
        },
    }
    df = dp.normalize_alerts([alert])
    row = df.iloc[0]
    assert row["attack_category"] == "DoS"
    assert row["mitre_source"] == "inferred"
    assert "T1498" in row["mitre_ids"]


def test_normalize_skips_non_dict_records(wazuh_bruteforce_alert):
    df = dp.normalize_alerts([wazuh_bruteforce_alert, "garbage", None, 42])
    assert len(df) == 1


def test_aggregations(wazuh_bruteforce_alert):
    # Two DISTINCT brute-force alerts (distinct id + timestamp) from the same IP.
    a2 = dict(wazuh_bruteforce_alert)
    a2["id"] = "1782000000.2"
    a2["timestamp"] = "2026-06-27T10:21:00.000+0000"
    df = dp.normalize_alerts([wazuh_bruteforce_alert, a2])
    dist = dp.attack_distribution(df)
    assert int(dist.loc[dist["attack_category"] == "Brute Force", "count"].iloc[0]) == 2

    tech = dp.mitre_technique_counts(df)
    assert "T1110" in set(tech["mitre_id"])

    srcs = dp.top_sources(df)
    assert srcs.iloc[0]["src_ip"] == "45.155.205.99"


def test_end_to_end_eve_pipeline(eve_file):
    """Real eve.json -> ingest -> normalize -> classified DataFrame."""
    alerts = ingest.load_alerts("suricata_eve", path=eve_file)
    df = dp.normalize_alerts(alerts)
    assert len(df) == 2
    assert df.iloc[0]["attack_category"] == "Scan"
    # The eve rule carried T1046 metadata, so provenance is rule-sourced.
    assert df.iloc[0]["mitre_source"] == "rule"
