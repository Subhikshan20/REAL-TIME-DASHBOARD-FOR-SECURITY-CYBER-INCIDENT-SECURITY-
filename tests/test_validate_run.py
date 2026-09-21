"""Tests for the pre-flight capture validator (validate_run.py)."""

from __future__ import annotations

import pandas as pd

import validate_run as vr


def _good_gt():
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


def test_check_ground_truth_accepts_valid():
    assert vr.check_ground_truth(_good_gt()) == []


def test_check_ground_truth_flags_placeholder_and_empty_benign():
    gt = _good_gt()
    gt["campaigns"][0]["source_ip"] = "REPLACE_WITH_ATTACKER_IP"
    gt["benign"]["benign_events"] = 0
    problems = vr.check_ground_truth(gt)
    assert any("placeholder" in p for p in problems)
    assert any("benign_events" in p for p in problems)


def test_check_ground_truth_flags_missing_campaigns():
    problems = vr.check_ground_truth({"benign": {"benign_events": 1}})
    assert any("campaigns" in p for p in problems)


def test_campaign_coverage_counts_in_window_alerts():
    df = pd.DataFrame(
        {
            "src_ip": ["1.1.1.1", "1.1.1.1", "9.9.9.9"],
            "timestamp": pd.to_datetime(
                [
                    "2026-06-27T10:05:00+0000",  # in window
                    "2026-06-27T11:00:00+0000",  # out of window
                    "2026-06-27T10:05:00+0000",  # wrong IP
                ],
                utc=True,
            ),
        }
    )
    cov = vr.campaign_coverage(df, _good_gt())
    assert cov[0]["alerts_in_window"] == 1
    assert cov[0]["alerts_from_ip"] == 2


def test_validate_mock_source_is_ready(tmp_path, monkeypatch):
    # A freshly-generated mock dataset is internally consistent -> exit code 0
    # (ready). Generate into a temp dir so the test never depends on the mutable
    # on-disk data/ (which the dashboard's data-reset can legitimately empty).
    import mock_data_generator as mdg
    from config import settings

    mdg.generate(out_dir=str(tmp_path), seed=42, randomize=False)
    monkeypatch.setattr(settings, "ALERTS_FILE", str(tmp_path / "wazuh_alerts.json"))
    monkeypatch.setattr(settings, "GROUND_TRUTH_FILE", str(tmp_path / "ground_truth.json"))
    assert vr.validate("mock", None, None) == 0
