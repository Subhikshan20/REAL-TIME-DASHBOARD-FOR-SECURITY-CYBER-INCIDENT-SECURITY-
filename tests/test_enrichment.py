"""Tests for IP/threat-intel enrichment (enrichment.py)."""

import enrichment

INDICATORS = [
    {
        "indicator": "45.155.205.99",
        "type": "ip",
        "tags": ["bruteforce"],
        "severity": "malicious",
        "confidence": 90,
    },
    {
        "indicator": "185.220.101.0/24",
        "type": "cidr",
        "tags": ["tor"],
        "severity": "suspicious",
        "confidence": 60,
    },
]


def test_ip_classification_private():
    c = enrichment.ip_classification("10.0.0.5")
    assert c["valid"] and c["is_private"] and c["scope"] == "private"


def test_ip_classification_public():
    c = enrichment.ip_classification("8.8.8.8")
    assert c["valid"] and not c["is_private"] and c["scope"] == "public"


def test_ip_classification_invalid():
    c = enrichment.ip_classification("not-an-ip")
    assert c["valid"] is False


def test_match_indicators_exact_ip():
    hit = enrichment.match_indicators("45.155.205.99", INDICATORS)
    assert hit is not None and hit["severity"] == "malicious"


def test_match_indicators_cidr():
    hit = enrichment.match_indicators("185.220.101.42", INDICATORS)
    assert hit is not None and "tor" in hit["tags"]


def test_match_indicators_miss():
    assert enrichment.match_indicators("1.2.3.4", INDICATORS) is None


def test_enrich_ip_malicious():
    e = enrichment.enrich_ip("45.155.205.99", INDICATORS)
    assert e["ti_verdict"] == "malicious"
    assert e["ti_source"] == "local-indicators"
    assert e["ti_confidence"] == 90


def test_enrich_ip_internal():
    e = enrichment.enrich_ip("10.0.0.5", INDICATORS)
    assert e["ti_verdict"] == "internal"
    assert e["is_private"] is True


def test_enrich_ip_unknown_public():
    e = enrichment.enrich_ip("203.0.113.200", INDICATORS)
    assert e["ti_verdict"] == "unknown"
    assert e["ti_tags"] == []
