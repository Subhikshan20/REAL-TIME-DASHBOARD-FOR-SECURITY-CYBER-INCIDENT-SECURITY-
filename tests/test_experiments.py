"""Tests for the repeated-run experiment framework (experiments.py)."""

import math

import experiments as ex


def test_t_critical_values():
    assert ex.t_critical_95(1) == 12.706
    assert ex.t_critical_95(9) == 2.262
    assert ex.t_critical_95(29) == 2.045
    assert ex.t_critical_95(40) == 1.96  # normal approximation beyond df=30
    assert math.isnan(ex.t_critical_95(0))


def test_generate_runs_and_list(tmp_path):
    runs_dir = str(tmp_path / "runs")
    created = ex.generate_runs(n=3, window_minutes=60, runs_dir=runs_dir)
    assert len(created) == 3
    found = ex.list_runs(runs_dir)
    assert len(found) == 3
    # Each run must carry its own ground truth + alerts.
    df, gt = ex.load_run(found[0])
    assert not df.empty
    assert "campaigns" in gt


def test_aggregate_runs_has_ci(tmp_path):
    runs_dir = str(tmp_path / "runs")
    ex.generate_runs(n=4, window_minutes=60, runs_dir=runs_dir)
    agg = ex.aggregate_runs(ex.list_runs(runs_dir))
    assert not agg.empty

    acc = agg[agg["metric"] == "Accuracy"].iloc[0]
    assert acc["n"] == 4
    assert 0.0 <= acc["mean"] <= 1.0
    # With n>1 a confidence interval must be produced and ordered correctly.
    assert acc["ci_halfwidth"] is not None
    assert acc["ci_low"] <= acc["mean"] <= acc["ci_high"]

    # The 3-way baseline recalls must be present in the aggregation.
    metrics = set(agg["metric"])
    assert "Event recall — Suricata-only (network)" in metrics
    assert "Event recall — Wazuh-only (host logs)" in metrics
    assert "Event recall — Correlated (fused)" in metrics


def test_aggregate_runs_empty():
    assert ex.aggregate_runs([]).empty
