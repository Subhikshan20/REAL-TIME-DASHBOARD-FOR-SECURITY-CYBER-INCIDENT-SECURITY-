"""Tests for P2 features: authentication and PDF export."""

import hashlib

import auth
import metrics as mx
import reporting


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
def test_verify_with_hash(monkeypatch):
    monkeypatch.setattr(auth.settings, "AUTH_USERNAME", "analyst")
    monkeypatch.setattr(auth.settings, "AUTH_PASSWORD_HASH", hashlib.sha256(b"s3cret").hexdigest())
    monkeypatch.setattr(auth.settings, "AUTH_PASSWORD", "")
    assert auth.verify("analyst", "s3cret") is True
    assert auth.verify("analyst", "wrong") is False
    assert auth.verify("attacker", "s3cret") is False


def test_verify_plaintext_fallback(monkeypatch):
    monkeypatch.setattr(auth.settings, "AUTH_USERNAME", "analyst")
    monkeypatch.setattr(auth.settings, "AUTH_PASSWORD_HASH", "")
    monkeypatch.setattr(auth.settings, "AUTH_PASSWORD", "pw")
    assert auth.verify("analyst", "pw") is True
    assert auth.verify("analyst", "nope") is False


def test_verify_denies_when_unconfigured(monkeypatch):
    monkeypatch.setattr(auth.settings, "AUTH_PASSWORD_HASH", "")
    monkeypatch.setattr(auth.settings, "AUTH_PASSWORD", "")
    assert auth.verify("analyst", "anything") is False


# --------------------------------------------------------------------------- #
# PDF export
# --------------------------------------------------------------------------- #
def test_pdf_report_is_valid_pdf(metrics_df, metrics_gt):
    bundle = mx.compute_all(metrics_df, metrics_gt)
    pdf = reporting.build_pdf_report(metrics_df, bundle, "Mock dataset")
    assert isinstance(pdf, bytes)
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 800


def test_pdf_report_without_bundle(metrics_df):
    pdf = reporting.build_pdf_report(metrics_df, None)
    assert pdf[:4] == b"%PDF"
