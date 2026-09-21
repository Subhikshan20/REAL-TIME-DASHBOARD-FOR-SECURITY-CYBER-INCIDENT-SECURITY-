"""
data_processor.py
=================
Turns canonical Wazuh alert documents (from any ingest source) into a tidy,
analysis-ready pandas DataFrame, classifies each alert into one of the four
dissertation attack categories, and enriches it with MITRE ATT&CK context.

Design notes
------------
* Classification uses alert *signals* (rule groups, signature text, ATT&CK ids)
  — i.e. exactly the interpretation a real SOC pipeline performs — never the
  embedded ground-truth label. The ground-truth label is reserved strictly for
  metric calculation in metrics.py.
* MITRE enrichment is explicit and honest: when a Suricata/Wazuh rule already
  carries ATT&CK technique ids those are used verbatim (``mitre_source="rule"``);
  when it does not, representative techniques are *inferred* from the classified
  attack category (``mitre_source="inferred"``) so the ATT&CK view is still
  populated for real eve.json. The provenance is surfaced in the DataFrame.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

import geo as geo_lookup
from logging_config import get_logger
from mitre_mapping import (
    MITRE_BY_ATTACK,
    TECHNIQUE_INDEX,
    infer_techniques,
    tactic_for_technique,
)

log = get_logger("data_processor")

# --------------------------------------------------------------------------- #
# Attack classification rules.
# Evaluated in PRIORITY order so the more specific categories win before the
# broad 'Scan' keyword set.
# --------------------------------------------------------------------------- #
_CLASSIFIER = {
    "Brute Force": {
        "mitre": {"T1110"},
        "groups": {"brute_force", "authentication_failures", "authentication_failed"},
        "keywords": [
            "bruteforce",
            "brute force",
            "login failure",
            "multiple ftp",
            "non-existent user",
        ],
    },
    "Exploit Delivery": {
        "mitre": {"T1190", "T1203", "T1059"},
        "groups": {"exploit", "web_attack", "command_execution", "fim"},
        "keywords": [
            "exploit",
            "rce",
            "sql injection",
            "log4j",
            "struts",
            "web shell",
            "ognl",
            "web_application_attack",
        ],
    },
    "DoS": {
        "mitre": {"T1498", "T1499"},
        "groups": {"dos", "flood"},
        "keywords": [
            "dos",
            "ddos",
            "flood",
            "slowloris",
            "syn flood",
            "mon_list",
            "denial of service",
        ],
    },
    "Scan": {
        "mitre": {"T1595", "T1046", "T1018"},
        "groups": {"recon", "network_scan"},
        "keywords": ["scan", "nmap", "recon", "sweep", "probe", "information leak"],
    },
}
ATTACK_CATEGORIES_PRIORITY = ["Brute Force", "Exploit Delivery", "DoS", "Scan"]


def classify_with_confidence(alert: dict[str, Any]) -> tuple[str, float]:
    """
    Classify an alert and return ``(category, confidence)``.

    Confidence reflects the strength of the matching signal so analysts can see
    how trustworthy each categorisation is:
        ATT&CK id match -> 0.95 · rule-group match -> 0.85 · keyword match -> 0.60
        no match ('Other') -> 0.0
    """
    rule = alert.get("rule", {}) or {}
    mitre_ids = set(rule.get("mitre", {}).get("id", []) or [])
    mitre_parents = {str(mid).split(".")[0] for mid in mitre_ids}
    groups = {str(g).lower() for g in rule.get("groups", []) or []}

    data = alert.get("data", {}) or {}
    net_alert = data.get("alert", {}) or {}
    text = " ".join(
        [
            str(rule.get("description", "")),
            str(net_alert.get("signature", "")),
            str(net_alert.get("category", "")),
        ]
    ).lower()

    for category in ATTACK_CATEGORIES_PRIORITY:
        rules = _CLASSIFIER[category]
        if mitre_parents & set(rules["mitre"]):
            return category, 0.95
        if groups & set(rules["groups"]):
            return category, 0.85
        if any(kw in text for kw in rules["keywords"]):
            return category, 0.60
    return "Other", 0.0


def classify_attack(alert: dict[str, Any]) -> str:
    """Map a single alert to one of the four attack categories (or 'Other')."""
    return classify_with_confidence(alert)[0]


def _severity_label(level: Any) -> str:
    """Map a Wazuh rule level to a coarse severity band for the UI."""
    try:
        lvl = int(level)
    except (TypeError, ValueError):
        return "Unknown"
    if lvl >= 12:
        return "Critical"
    if lvl >= 8:
        return "High"
    if lvl >= 5:
        return "Medium"
    return "Low"


def _enrich_mitre(alert: dict[str, Any], attack_category: str) -> dict[str, Any]:
    """
    Resolve MITRE technique ids / tactics / names for an alert.

    Returns a dict with keys: ids, tactics, techniques, source.
    """
    mitre = alert.get("rule", {}).get("mitre", {}) or {}
    ids = [i for i in (mitre.get("id") or []) if i]

    if ids:
        # Rule already carries ATT&CK ids — trust them, fill any gaps.
        tactics = [t for t in (mitre.get("tactic") or []) if t]
        if not tactics:
            tactics = sorted({tactic_for_technique(i) for i in ids} - {"Unknown"})
        techniques = [t for t in (mitre.get("technique") or []) if t]
        if not techniques:
            techniques = [TECHNIQUE_INDEX.get(i, {}).get("name", i) for i in ids]
        return {"ids": ids, "tactics": tactics, "techniques": techniques, "source": "rule"}

    # No ATT&CK metadata on the rule — infer from the classified attack type.
    if attack_category in MITRE_BY_ATTACK:
        techs = MITRE_BY_ATTACK[attack_category]
        return {
            "ids": [t["id"] for t in techs],
            "tactics": list(dict.fromkeys(t["tactic"] for t in techs)),
            "techniques": [t["name"] for t in techs],
            "source": "inferred",
        }

    # 'Other' (outside the four studied attacks): map from rule classtype /
    # signature keywords so real eve.json still gets ATT&CK context.
    rule = alert.get("rule", {}) or {}
    net_alert = (alert.get("data", {}) or {}).get("alert", {}) or {}
    techs = infer_techniques(
        net_alert.get("category", ""),
        rule.get("groups", []) or [],
        net_alert.get("signature", "") or rule.get("description", ""),
    )
    if techs:
        return {
            "ids": [t["id"] for t in techs],
            "tactics": list(dict.fromkeys(t["tactic"] for t in techs)),
            "techniques": [t["name"] for t in techs],
            "source": "inferred",
        }

    return {"ids": [], "tactics": [], "techniques": [], "source": "none"}


def _flatten(alert: dict[str, Any]) -> dict[str, Any]:
    """Flatten one nested alert document into a single analysis row."""
    rule = alert.get("rule", {}) or {}
    data = alert.get("data", {}) or {}
    net_alert = data.get("alert", {}) or {}

    category, confidence = classify_with_confidence(alert)
    mitre = _enrich_mitre(alert, category)

    return {
        "timestamp": alert.get("timestamp"),
        "alert_id": alert.get("id"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "severity": _severity_label(rule.get("level")),
        "description": rule.get("description"),
        "groups": ", ".join(rule.get("groups", []) or []),
        "agent": (alert.get("agent", {}) or {}).get("name"),
        "decoder": (alert.get("decoder", {}) or {}).get("name"),
        "location": alert.get("location"),
        "src_ip": data.get("srcip"),
        "src_port": data.get("src_port"),
        "dest_ip": data.get("dest_ip") or data.get("dstip"),
        "dest_port": data.get("dest_port"),
        "proto": data.get("proto"),
        "flow_id": data.get("flow_id"),
        # Source geolocation when the IDS/SIEM enriched the alert (GeoLocation).
        "src_country": (alert.get("GeoLocation", {}) or {}).get("country_name"),
        "signature": net_alert.get("signature"),
        "signature_category": net_alert.get("category"),
        "attack_category": category,
        "classification_confidence": confidence,
        "mitre_ids": mitre["ids"],
        "mitre_tactics": mitre["tactics"],
        "mitre_techniques": mitre["techniques"],
        "mitre_source": mitre["source"],
        # Ground-truth label (mock / labelled data only) — used solely by metrics.
        "is_true_positive": (alert.get("validation", {}) or {}).get("is_true_positive"),
    }


_COLUMNS = [
    "timestamp",
    "alert_id",
    "rule_id",
    "rule_level",
    "severity",
    "description",
    "groups",
    "agent",
    "decoder",
    "location",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "proto",
    "flow_id",
    "src_country",
    "signature",
    "signature_category",
    "attack_category",
    "classification_confidence",
    "mitre_ids",
    "mitre_tactics",
    "mitre_techniques",
    "mitre_source",
    "is_true_positive",
]

# Columns whose exact repetition means the same alert was re-fetched (e.g. across
# refreshes / tailing) and should be de-duplicated.
_DEDUP_KEYS = ["alert_id", "timestamp", "rule_id", "src_ip", "dest_ip", "signature"]


def normalize_alerts(alerts: list[dict[str, Any]]) -> pd.DataFrame:
    """Convert a list of canonical alert documents into a typed, sorted frame."""
    if not alerts:
        return pd.DataFrame(columns=_COLUMNS)

    rows: list[dict[str, Any]] = []
    bad = 0
    for a in alerts:
        if not isinstance(a, dict):
            bad += 1
            continue
        try:
            rows.append(_flatten(a))
        except Exception as exc:  # never let one odd record break the batch
            bad += 1
            log.debug("Skipping unparseable alert: %s", exc)
    if bad:
        log.warning("normalize_alerts: skipped %d malformed alert record(s)", bad)

    if not rows:
        return pd.DataFrame(columns=_COLUMNS)

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["rule_level"] = pd.to_numeric(df["rule_level"], errors="coerce")

    # De-duplicate identical alerts re-fetched across refreshes / tailing.
    before = len(df)
    df = df.drop_duplicates(subset=_DEDUP_KEYS, keep="first")
    removed = before - len(df)
    if removed:
        log.info("De-duplicated %d repeated alert(s).", removed)

    df = df.sort_values("timestamp", ascending=False).reset_index(drop=True)
    log.info("Normalized %d alerts into DataFrame (%d columns).", len(df), df.shape[1])
    return df


# --------------------------------------------------------------------------- #
# Aggregations consumed by the dashboard
# --------------------------------------------------------------------------- #
def attack_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Count of alerts per attack category."""
    if df.empty:
        return pd.DataFrame(columns=["attack_category", "count"])
    return (
        df["attack_category"]
        .value_counts()
        .rename_axis("attack_category")
        .reset_index(name="count")
    )


def alerts_over_time(df: pd.DataFrame, freq: str = "1min") -> pd.DataFrame:
    """Time-bucketed alert counts per attack category (for the timeline chart)."""
    if df.empty:
        return pd.DataFrame(columns=["time_bucket", "attack_category", "count"])
    tmp = df.dropna(subset=["timestamp"]).copy()
    if tmp.empty:
        return pd.DataFrame(columns=["time_bucket", "attack_category", "count"])
    tmp["time_bucket"] = tmp["timestamp"].dt.floor(freq)
    return tmp.groupby(["time_bucket", "attack_category"]).size().reset_index(name="count")


def mitre_technique_counts(df: pd.DataFrame) -> pd.DataFrame:
    """Explode mitre technique ids into a per-technique count table."""
    if df.empty:
        return pd.DataFrame(columns=["mitre_id", "count"])
    exploded = df.explode("mitre_ids").dropna(subset=["mitre_ids"])
    exploded = exploded[exploded["mitre_ids"] != ""]
    if exploded.empty:
        return pd.DataFrame(columns=["mitre_id", "count"])
    return exploded["mitre_ids"].value_counts().rename_axis("mitre_id").reset_index(name="count")


def mitre_tactic_counts(df: pd.DataFrame) -> pd.DataFrame:
    """Explode mitre tactics into a per-tactic count table."""
    if df.empty:
        return pd.DataFrame(columns=["tactic", "count"])
    exploded = df.explode("mitre_tactics").dropna(subset=["mitre_tactics"])
    exploded = exploded[exploded["mitre_tactics"] != ""]
    if exploded.empty:
        return pd.DataFrame(columns=["tactic", "count"])
    return exploded["mitre_tactics"].value_counts().rename_axis("tactic").reset_index(name="count")


def top_sources(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Most active source IPs (attacker hosts)."""
    if df.empty or "src_ip" not in df:
        return pd.DataFrame(columns=["src_ip", "count"])
    return (
        df.dropna(subset=["src_ip"])["src_ip"]
        .value_counts()
        .head(n)
        .rename_axis("src_ip")
        .reset_index(name="count")
    )


def country_counts(df: pd.DataFrame) -> pd.DataFrame:
    """Alert counts per source country (for the GeoIP choropleth).

    Includes an ``iso3`` column (ISO 3166-1 alpha-3) so the choropleth can use
    ``locationmode="ISO-3"`` instead of Plotly's deprecated country-name matcher.
    """
    if df.empty or "src_country" not in df:
        return pd.DataFrame(columns=["country", "count", "iso3"])
    geo = df.dropna(subset=["src_country"])
    geo = geo[geo["src_country"].astype(str).str.strip() != ""]
    if geo.empty:
        return pd.DataFrame(columns=["country", "count", "iso3"])
    out = geo["src_country"].value_counts().rename_axis("country").reset_index(name="count")
    out["iso3"] = out["country"].map(geo_lookup.to_iso3)
    return out
