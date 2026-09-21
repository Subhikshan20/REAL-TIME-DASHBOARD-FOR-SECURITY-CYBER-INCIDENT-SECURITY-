"""Tests for the added features: GeoIP extraction and the Markdown report."""

import data_processor as dp
import metrics as mx
import reporting


def _geo_alert(country, src, alert_id):
    return {
        "timestamp": "2026-06-27T10:00:00.000+0000",
        "id": alert_id,
        "agent": {"name": "suricata-sensor"},
        "rule": {
            "id": "1",
            "level": 8,
            "description": "ET SCAN nmap",
            "groups": ["ids", "suricata", "recon"],
            "mitre": {"id": ["T1046"], "tactic": [], "technique": []},
        },
        "decoder": {"name": "suricata"},
        "data": {
            "srcip": src,
            "dest_ip": "10.0.0.5",
            "alert": {"signature": "ET SCAN nmap", "category": "x"},
        },
        "GeoLocation": {"country_name": country},
    }


def _geo_set():
    # Three DISTINCT alerts (distinct ids + source IPs) — two from Russia, one CN.
    return [
        _geo_alert("Russia", "203.0.113.7", "a1"),
        _geo_alert("China", "198.51.100.23", "a2"),
        _geo_alert("Russia", "192.0.2.66", "a3"),
    ]


def test_src_country_extracted():
    df = dp.normalize_alerts(_geo_set())
    assert "src_country" in df.columns
    assert set(df["src_country"]) == {"Russia", "China"}


def test_country_counts():
    df = dp.normalize_alerts(_geo_set())
    counts = dp.country_counts(df)
    assert int(counts.loc[counts["country"] == "Russia", "count"].iloc[0]) == 2
    # ISO-3 column populated for the choropleth (no deprecated name matcher).
    assert "iso3" in counts.columns
    assert counts.loc[counts["country"] == "Russia", "iso3"].iloc[0] == "RUS"
    assert counts.loc[counts["country"] == "China", "iso3"].iloc[0] == "CHN"


def test_geo_to_iso3_handles_names_and_aliases():
    import geo

    assert geo.to_iso3("United States") == "USA"
    assert geo.to_iso3("usa") == "USA"  # alias
    assert geo.to_iso3("Russian Federation") == "RUS"  # alias
    assert geo.to_iso3("South Korea") == "KOR"
    assert geo.to_iso3("  netherlands  ") == "NLD"  # case/space tolerant
    assert geo.to_iso3("Atlantis") is None  # unknown -> omitted from map
    assert geo.to_iso3(None) is None


def test_country_counts_empty_when_no_geo(wazuh_bruteforce_alert):
    # The brute-force fixture has no GeoLocation -> empty geo frame.
    df = dp.normalize_alerts([wazuh_bruteforce_alert])
    assert dp.country_counts(df).empty


def test_report_contains_metrics(metrics_df, metrics_gt):
    bundle = mx.compute_all(metrics_df, metrics_gt)
    md = reporting.build_markdown_report(metrics_df, bundle, source_label="Mock dataset")
    assert "# SOC Detection Report" in md
    assert "Accuracy" in md
    assert "Confusion matrix" in md
    assert "Mean Time To Detect" in md
    assert "Brute Force" in md


def test_report_without_bundle(metrics_df):
    md = reporting.build_markdown_report(metrics_df, None)
    assert "Objective metrics unavailable" in md
