"""
Tests for the objective metric calculations (metrics.py).

Every metric is computed dynamically from the alert stream; the fixtures provide
a hand-built stream whose expected numbers are derived by hand in conftest.
"""

import math

import data_processor as dp
import metrics as mx


# --------------------------------------------------------------------------- #
# Confusion matrix + classification (computed from the stream)
# --------------------------------------------------------------------------- #
def test_confusion_matrix_dynamic(metrics_df, metrics_gt):
    cm = mx.confusion_matrix(metrics_df, metrics_gt)
    assert cm == {"TP": 3, "FP": 1, "TN": 99, "FN": 7}


def test_classification_metrics_values(metrics_df, metrics_gt):
    cm = mx.confusion_matrix(metrics_df, metrics_gt)
    clf = mx.classification_metrics(cm)
    assert math.isclose(clf["accuracy"], 102 / 110, abs_tol=1e-9)
    assert math.isclose(clf["precision"], 0.75, abs_tol=1e-9)
    assert math.isclose(clf["recall"], 0.3, abs_tol=1e-9)
    assert math.isclose(clf["fpr"], 0.01, abs_tol=1e-9)


def test_classification_metrics_handle_zero_division():
    clf = mx.classification_metrics({"TP": 0, "FP": 0, "TN": 0, "FN": 0})
    assert clf["accuracy"] == 0.0
    assert clf["precision"] == 0.0
    assert clf["fpr"] == 0.0


# --------------------------------------------------------------------------- #
# Alert→campaign matching is window + IP bound
# --------------------------------------------------------------------------- #
def test_alert_outside_window_is_false_positive(metrics_gt):
    # Same attacker IP but 30 min after the window closes -> must NOT be a TP.
    late = {
        "timestamp": "2026-06-27T10:40:00.000+0000",
        "agent": {"name": "suricata-sensor"},
        "rule": {
            "id": "1",
            "level": 10,
            "description": "ET SCAN ssh bruteforce",
            "groups": ["ids", "suricata", "brute_force"],
            "mitre": {"id": ["T1110"], "tactic": [], "technique": []},
        },
        "decoder": {"name": "suricata"},
        "data": {
            "srcip": "1.1.1.1",
            "dest_ip": "2.2.2.2",
            "alert": {"signature": "ET SCAN ssh bruteforce", "category": "x"},
        },
    }
    df = dp.normalize_alerts([late])
    cm = mx.confusion_matrix(df, metrics_gt)
    assert cm["TP"] == 0
    assert cm["FP"] == 1


# --------------------------------------------------------------------------- #
# MTTD (computed from real timestamps)
# --------------------------------------------------------------------------- #
def test_mttd_dynamic(metrics_df, metrics_gt):
    row = mx.mttd(metrics_df, metrics_gt).iloc[0]
    assert row["network_mttd_s"] == 5.0
    assert row["host_mttd_s"] == 20.0
    assert row["correlated_mttd_s"] == 5.0
    assert row["baseline_mttd_s"] == 20.0
    assert row["improvement_s"] == 15.0
    assert row["improvement_pct"] == 75.0


def test_mttd_host_only_miss(metrics_gt):
    # Network-only detections -> host baseline undefined, flagged accordingly.
    net = {
        "timestamp": "2026-06-27T10:00:09.000+0000",
        "agent": {"name": "suricata-sensor"},
        "rule": {
            "id": "1",
            "level": 10,
            "description": "ET DOS SYN flood",
            "groups": ["ids", "suricata", "dos"],
            "mitre": {"id": ["T1498"], "tactic": [], "technique": []},
        },
        "decoder": {"name": "suricata"},
        "data": {
            "srcip": "1.1.1.1",
            "dest_ip": "2.2.2.2",
            "alert": {"signature": "ET DOS SYN flood", "category": "x"},
        },
    }
    df = dp.normalize_alerts([net])
    row = mx.mttd(df, metrics_gt).iloc[0]
    assert row["network_mttd_s"] == 9.0
    assert row["host_mttd_s"] is None
    assert row["improvement_s"] is None
    assert "host-only" in row["note"]


def test_mttd_summary(metrics_df, metrics_gt):
    summ = mx.mttd_summary(mx.mttd(metrics_df, metrics_gt))
    assert summ["mean_correlated_mttd_s"] == 5.0
    assert summ["mean_improvement_pct"] == 75.0


# --------------------------------------------------------------------------- #
# Per-attack + the one-call bundle
# --------------------------------------------------------------------------- #
def test_per_attack_detection(metrics_df, metrics_gt):
    row = mx.per_attack_detection(metrics_df, metrics_gt).iloc[0]
    assert row["malicious_events"] == 10
    assert row["detected"] == 3
    assert row["missed"] == 7
    assert math.isclose(row["detection_rate"], 0.3, abs_tol=1e-9)


def test_compute_all_empty():
    bundle = mx.compute_all(dp.normalize_alerts([]), {})
    assert bundle["confusion_matrix"] == {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    assert bundle["mttd"].empty
    assert bundle["config_comparison"].empty
    assert bundle["correlation_value"]["num_incidents"] == 0


# --------------------------------------------------------------------------- #
# 3-way configuration comparison
# --------------------------------------------------------------------------- #
def test_configuration_comparison(metrics_df, metrics_gt):
    cfg = mx.configuration_comparison(metrics_df, metrics_gt).set_index("configuration")
    # Suricata-only sees the 3 network alerts; Wazuh-only sees the 1 host alert.
    net = cfg.loc["Suricata-only (network)"]
    host = cfg.loc["Wazuh-only (host logs)"]
    corr = cfg.loc["Correlated (fused)"]
    assert net["events_detected"] == 3 and net["mean_mttd_s"] == 5.0
    assert host["events_detected"] == 1 and host["mean_mttd_s"] == 20.0
    assert corr["events_detected"] == 3 and corr["mean_mttd_s"] == 5.0
    assert net["total_events"] == 10


# --------------------------------------------------------------------------- #
# Correlation value
# --------------------------------------------------------------------------- #
def test_correlation_value(metrics_df, metrics_gt):
    cv = mx.correlation_value(metrics_df, metrics_gt)
    assert cv["total_alerts"] == 5
    # 1 true incident (the campaign) + 1 FP cluster (the 9.9.9.9 benign alert)
    assert cv["true_incidents"] == 1
    assert cv["fp_incidents"] == 1
    assert cv["num_incidents"] == 2
    assert cv["alert_to_incident_ratio"] == 2.5
    assert cv["multi_source_incidents"] == 1  # both network and host fired
    assert cv["missed_by_host_only"] == 0
    assert cv["missed_by_network_only"] == 0
