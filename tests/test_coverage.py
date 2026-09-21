"""
Verifies the mock dataset demonstrates genuine correlation coverage — i.e. the
correlated view detects incidents that neither single source catches alone.
"""

import os

import data_processor as dp
import ingest
import metrics as mx
import mock_data_generator as mdg


def _load(out_dir):
    alerts = ingest.read_mock_alerts(os.path.join(out_dir, "wazuh_alerts.json"))
    gt = ingest.load_ground_truth(os.path.join(out_dir, "ground_truth.json"))
    return dp.normalize_alerts(alerts), gt


def test_correlation_beats_both_single_sources(tmp_path):
    out = str(tmp_path / "ds")
    mdg.generate(out_dir=out, seed=42, randomize=False)
    df, gt = _load(out)

    cv = mx.correlation_value(df, gt)
    # Network-only misses the encrypted brute force; host-only misses scan + DoS.
    assert cv["missed_by_network_only"] >= 1
    assert cv["missed_by_host_only"] >= 1
    # Correlated strictly beats each single source on incident coverage.
    assert cv["detected_by_correlated"] > cv["detected_by_suricata"]
    assert cv["detected_by_correlated"] > cv["detected_by_wazuh"]


def test_configuration_comparison_ranks_correlated_top(tmp_path):
    out = str(tmp_path / "ds")
    mdg.generate(out_dir=out, seed=7, randomize=True)
    df, gt = _load(out)

    cfg = mx.configuration_comparison(df, gt).set_index("configuration")
    corr = cfg.loc["Correlated (fused)", "incident_detection_rate"]
    net = cfg.loc["Suricata-only (network)", "incident_detection_rate"]
    host = cfg.loc["Wazuh-only (host logs)", "incident_detection_rate"]
    assert corr >= net and corr >= host
    assert corr > min(net, host)
