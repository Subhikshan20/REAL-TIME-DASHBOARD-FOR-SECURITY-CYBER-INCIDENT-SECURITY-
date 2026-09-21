"""Tests for the analysis additions: noisy-rule ranking, sensitivity analysis,
and the pipeline throughput benchmark."""

from __future__ import annotations

import os

import pytest

import benchmark as bm
import data_processor as dp
import ingest
import metrics as mx
import mock_data_generator as mdg


@pytest.fixture
def mock_df_gt(tmp_path):
    """A deterministic, ISOLATED mock dataset — never reads the mutable project
    ``data/`` (which a developer may have emptied via the app's "Reset data"),
    so these tests are hermetic and reproducible."""
    out = str(tmp_path / "ds")
    mdg.generate(out_dir=out, seed=42, randomize=False)
    df = dp.normalize_alerts(ingest.read_mock_alerts(os.path.join(out, "wazuh_alerts.json")))
    gt = ingest.load_ground_truth(os.path.join(out, "ground_truth.json"))
    return df, gt


# --------------------------- noisy_rules ---------------------------------- #
def test_noisy_rules_ranks_false_positives(mock_df_gt):
    df, gt = mock_df_gt
    nr = mx.noisy_rules(df, gt, top=10)
    assert list(nr.columns) == ["signature", "alerts", "false_positives", "fp_rate"]
    assert len(nr) <= 10
    # Sorted by false positives descending.
    fps = nr["false_positives"].tolist()
    assert fps == sorted(fps, reverse=True)
    # FP rate is a valid proportion, never exceeding the alert count.
    assert ((nr["fp_rate"] >= 0) & (nr["fp_rate"] <= 1)).all()
    assert (nr["false_positives"] <= nr["alerts"]).all()


def test_noisy_rules_empty_inputs():
    import pandas as pd

    assert mx.noisy_rules(pd.DataFrame(), {}).empty


# --------------------------- sensitivity ---------------------------------- #
def test_sensitivity_analysis_responds_to_benign_volume(mock_df_gt):
    df, gt = mock_df_gt
    sa = mx.sensitivity_analysis(df, gt, [2000, 5000, 10000, 20000])
    assert list(sa.columns) == ["benign_events", "accuracy", "fpr", "precision", "f1"]
    assert len(sa) == 4
    # More benign traffic (with FP count fixed) lowers the false-positive rate.
    fpr = sa.sort_values("benign_events")["fpr"].tolist()
    assert fpr == sorted(fpr, reverse=True)
    assert all(0.0 <= v <= 1.0 for v in sa["fpr"])


def test_sensitivity_analysis_empty_inputs():
    import pandas as pd

    assert mx.sensitivity_analysis(pd.DataFrame(), {}, [1, 2]).empty


# --------------------------- benchmark ------------------------------------ #
def test_run_benchmark_reports_timings_and_throughput():
    df = bm.run_benchmark(sizes=(200, 500), repeats=1)
    assert list(df.columns) == [
        "alerts",
        "normalise_ms",
        "metrics_ms",
        "total_ms",
        "throughput_per_s",
    ]
    assert df["alerts"].tolist() == [200, 500]
    # All timings are non-negative and throughput is positive.
    assert (df["total_ms"] >= 0).all()
    assert (df["throughput_per_s"] > 0).all()
