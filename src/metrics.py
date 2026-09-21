"""
metrics.py
==========
Objective SOC evaluation metrics — **computed dynamically from the live alert
stream**, never from pre-authored result numbers.

Detection accuracy, false-positive rate, recall/precision and Mean-Time-To-Detect
are all derived at query time from:

  1. the normalised alert DataFrame produced by data_processor (the real, dynamic
     detections), and
  2. a small *measured* ground-truth facts file describing only what the lab
     analyst genuinely knows about their own actions — per attack campaign: the
     attacker source IP, the start/end window, and how many malicious events were
     launched (``malicious_attempts``); plus the total volume of benign traffic.

From those two inputs the dashboard works everything out itself:

  * Alerts are matched to a campaign when their source IP and timestamp fall
    inside that campaign's window  → these are true positives.
  * Alerts that match no campaign  → false positives (benign traffic that alerted).
  * Detections / first-detection times / MTTD come straight from the matched
    alert timestamps.
  * Missed events (false negatives) = launched attempts − detected; benign that
    correctly stayed silent (true negatives) = benign volume − false positives.

Nothing here is hard-coded per attack: change the alert stream and every number
changes. The same code path runs identically for mock, eve.json and live data.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from logging_config import get_logger

log = get_logger("metrics")


def _parse_ts(value: Any) -> pd.Timestamp:
    return pd.to_datetime(value, utc=True, errors="coerce")


def _campaigns(ground_truth: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse the measured campaign facts into a convenient internal form."""
    out: list[dict[str, Any]] = []
    for c in ground_truth.get("campaigns", []):
        out.append(
            {
                "attack_type": c.get("attack_type", "Unknown"),
                "source_ip": c.get("source_ip"),
                "start": _parse_ts(c.get("start_time")),
                "end": _parse_ts(c.get("end_time")) if c.get("end_time") else None,
                "malicious_attempts": int(c.get("malicious_attempts", 0)),
            }
        )
    return out


def _benign_volume(ground_truth: dict[str, Any]) -> int:
    """Total benign events observed in the window (analyst-measured)."""
    b = ground_truth.get("benign", {})
    return int(b.get("benign_events", b.get("total_events", 0)))


def _is_network_layer(decoder: Any, agent: Any) -> bool:
    """True for Suricata network detections; False for Wazuh host-log decoders."""
    d = str(decoder or "").lower()
    a = str(agent or "").lower()
    return d == "suricata" or "sensor" in a


# --------------------------------------------------------------------------- #
# Step 1 — match each alert to a campaign (or mark it a false positive)
# --------------------------------------------------------------------------- #
def label_alerts(df: pd.DataFrame, ground_truth: dict[str, Any]) -> pd.DataFrame:
    """
    Return a copy of ``df`` annotated with:
      * ``matched_idx``  — index of the campaign an alert belongs to, or -1.
      * ``source_layer`` — "network" (Suricata) or "host" (Wazuh decoders).
    Matching is purely data-driven: attacker source IP + time window.
    """
    work = df.copy()
    if work.empty:
        work["matched_idx"] = pd.Series(dtype="int64")
        work["source_layer"] = pd.Series(dtype="object")
        return work

    camps = _campaigns(ground_truth)

    # Vectorised attribution: build a per-campaign boolean mask (source IP within
    # the time window) and assign the first matching campaign to each alert. This
    # replaces a per-row Python loop and scales to large alert volumes.
    ts = work["timestamp"]
    sip = work["src_ip"]
    matched = pd.Series(-1, index=work.index, dtype="int64")
    for j, c in enumerate(camps):
        if pd.isna(c["start"]) or c["source_ip"] is None:
            continue
        mask = (sip == c["source_ip"]) & ts.notna() & (ts >= c["start"])
        if c["end"] is not None:
            mask &= ts <= c["end"]
        mask &= matched == -1  # first match wins
        matched[mask] = j
    work["matched_idx"] = matched

    # Vectorised layer classification (network = Suricata sensor, else host).
    dec = work["decoder"].astype(str).str.lower()
    ag = work["agent"].astype(str).str.lower()
    is_net = (dec == "suricata") | ag.str.contains("sensor", na=False)
    work["source_layer"] = is_net.map({True: "network", False: "host"})
    return work


# --------------------------------------------------------------------------- #
# Step 2 — confusion matrix + classification metrics (computed)
# --------------------------------------------------------------------------- #
def _detected_count(sub: pd.DataFrame) -> int:
    """
    Distinct malicious events detected within a campaign.

    Counted at the network-detection granularity (one Suricata alert == one
    detected malicious flow). Host-log alerts corroborate the same events, so
    they are not double-counted; if a campaign produced no network alerts the
    host alerts are used instead.
    """
    net = int((sub["source_layer"] == "network").sum())
    return net if net > 0 else len(sub)


def confusion_matrix(df: pd.DataFrame, ground_truth: dict[str, Any]) -> dict[str, int]:
    """Compute TP/FP/TN/FN live from the matched alert stream + measured totals."""
    if df.empty or not ground_truth:
        return {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

    labeled = label_alerts(df, ground_truth)
    camps = _campaigns(ground_truth)

    tp = 0
    fn = 0
    for j, c in enumerate(camps):
        sub = labeled[labeled["matched_idx"] == j]
        detected = _detected_count(sub)
        attempts = c["malicious_attempts"]
        if attempts:
            detected = min(detected, attempts)
            fn += max(attempts - detected, 0)
        tp += detected

    fp = int((labeled["matched_idx"] == -1).sum())
    benign = _benign_volume(ground_truth)
    if benign:
        fp = min(fp, benign)
        tn = max(benign - fp, 0)
    else:
        tn = 0  # benign volume unknown -> TN/accuracy/FPR are not defined

    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn}


def classification_metrics(cm: dict[str, int]) -> dict[str, float]:
    """Accuracy, precision, recall, F1, FPR and specificity from a confusion matrix."""
    tp, fp, tn, fn = cm["TP"], cm["FP"], cm["TN"], cm["FN"]
    total = tp + fp + tn + fn

    def safe_div(a: float, b: float) -> float:
        return a / b if b else 0.0

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)  # detection rate / sensitivity
    return {
        "accuracy": safe_div(tp + tn, total),
        "precision": precision,
        "recall": recall,
        "f1": safe_div(2 * precision * recall, precision + recall),
        "fpr": safe_div(fp, fp + tn),
        "specificity": safe_div(tn, tn + fp),
        "total_events": total,
    }


# --------------------------------------------------------------------------- #
# Per-attack detection performance (computed)
# --------------------------------------------------------------------------- #
def per_attack_detection(df: pd.DataFrame, ground_truth: dict[str, Any]) -> pd.DataFrame:
    """Detected / missed / detection-rate per campaign, derived from the stream."""
    if df.empty or not ground_truth:
        return pd.DataFrame(
            columns=["attack_type", "malicious_events", "detected", "missed", "detection_rate"]
        )

    labeled = label_alerts(df, ground_truth)
    camps = _campaigns(ground_truth)

    rows: list[dict[str, Any]] = []
    for j, c in enumerate(camps):
        sub = labeled[labeled["matched_idx"] == j]
        detected = _detected_count(sub)
        attempts = c["malicious_attempts"] or detected
        detected = min(detected, attempts) if attempts else detected
        rows.append(
            {
                "attack_type": c["attack_type"],
                "malicious_events": attempts,
                "detected": detected,
                "missed": max(attempts - detected, 0),
                "detection_rate": (detected / attempts) if attempts else 0.0,
            }
        )
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- #
# Mean Time To Detect — computed from real alert timestamps
# --------------------------------------------------------------------------- #
def mttd(df: pd.DataFrame, ground_truth: dict[str, Any]) -> pd.DataFrame:
    """
    Per campaign, derive MTTD from the actual matched alert timestamps:

      * network_mttd_s  — first Suricata (network) alert  − attack start
      * host_mttd_s     — first Wazuh host-log alert       − attack start
      * correlated_mttd_s — first alert from *either* layer (the fused SOC)
      * improvement_*   — reduction of the correlated detection vs the
                          host-log-only baseline (a traditional SIEM without the
                          network sensor). Where host logs never fire, the attack
                          is flagged as detectable only via the correlated/network
                          path.
    """
    cols = [
        "attack_type",
        "network_mttd_s",
        "host_mttd_s",
        "correlated_mttd_s",
        "baseline_mttd_s",
        "improvement_s",
        "improvement_pct",
        "detected",
        "note",
    ]
    if df.empty or not ground_truth:
        return pd.DataFrame(columns=cols)

    labeled = label_alerts(df, ground_truth)
    camps = _campaigns(ground_truth)

    rows: list[dict[str, Any]] = []
    for j, c in enumerate(camps):
        sub = labeled[labeled["matched_idx"] == j]
        start = c["start"]
        if sub.empty or pd.isna(start):
            rows.append(
                {
                    **{k: None for k in cols},
                    "attack_type": c["attack_type"],
                    "detected": False,
                    "note": "no alerts matched",
                }
            )
            continue

        net_ts = sub.loc[sub["source_layer"] == "network", "timestamp"]
        host_ts = sub.loc[sub["source_layer"] == "host", "timestamp"]

        net_first = (net_ts.min() - start).total_seconds() if not net_ts.empty else None
        host_first = (host_ts.min() - start).total_seconds() if not host_ts.empty else None

        candidates = [x for x in (net_first, host_first) if x is not None]
        correlated = min(candidates) if candidates else None
        baseline = host_first  # traditional host-log-only SIEM

        if baseline is not None and correlated is not None:
            improvement = baseline - correlated
            improvement_pct = (improvement / baseline * 100.0) if baseline else None
            note = ""
        else:
            improvement = None
            improvement_pct = None
            note = "host-only SIEM would miss this (network/correlation required)"

        rows.append(
            {
                "attack_type": c["attack_type"],
                "network_mttd_s": round(net_first, 1) if net_first is not None else None,
                "host_mttd_s": round(host_first, 1) if host_first is not None else None,
                "correlated_mttd_s": round(correlated, 1) if correlated is not None else None,
                "baseline_mttd_s": round(baseline, 1) if baseline is not None else None,
                "improvement_s": round(improvement, 1) if improvement is not None else None,
                "improvement_pct": (
                    round(improvement_pct, 1) if improvement_pct is not None else None
                ),
                "detected": True,
                "note": note,
            }
        )
    return pd.DataFrame(rows)


def mttd_summary(mttd_df: pd.DataFrame) -> dict[str, float]:
    """Headline MTTD numbers, averaged only over campaigns where each is defined."""
    if mttd_df.empty:
        return {
            "mean_correlated_mttd_s": 0.0,
            "mean_baseline_mttd_s": 0.0,
            "mean_improvement_s": 0.0,
            "mean_improvement_pct": 0.0,
        }

    corr = mttd_df["correlated_mttd_s"].dropna()
    base = mttd_df["baseline_mttd_s"].dropna()
    imp = mttd_df["improvement_s"].dropna()
    imp_pct = mttd_df["improvement_pct"].dropna()
    return {
        "mean_correlated_mttd_s": round(corr.mean(), 1) if not corr.empty else 0.0,
        "mean_baseline_mttd_s": round(base.mean(), 1) if not base.empty else 0.0,
        "mean_improvement_s": round(imp.mean(), 1) if not imp.empty else 0.0,
        "mean_improvement_pct": round(imp_pct.mean(), 1) if not imp_pct.empty else 0.0,
    }


# --------------------------------------------------------------------------- #
# Justified 3-way baseline: Suricata-only vs Wazuh-only vs Correlated
# --------------------------------------------------------------------------- #
def configuration_comparison(df: pd.DataFrame, ground_truth: dict[str, Any]) -> pd.DataFrame:
    """
    Compare the three detection configurations head-to-head, all from the same
    alert stream:

      * **Suricata-only (network)** — only the IDS network signatures are available.
      * **Wazuh-only (host logs)**  — only the host-log decoders are available
                                      (a traditional log-based SIEM).
      * **Correlated (fused)**      — both layers combined (this dashboard).

    For each, the incident-level detection rate, event-level recall and mean MTTD
    are reported, so the value of correlation over either single source is
    explicit and measured rather than assumed.
    """
    cols = [
        "configuration",
        "incidents_detected",
        "total_incidents",
        "incident_detection_rate",
        "events_detected",
        "total_events",
        "event_recall",
        "mean_mttd_s",
    ]
    if df.empty or not ground_truth:
        return pd.DataFrame(columns=cols)

    labeled = label_alerts(df, ground_truth)
    camps = _campaigns(ground_truth)
    total_incidents = len(camps)
    total_events = sum(c["malicious_attempts"] for c in camps)

    configs = {
        "Suricata-only (network)": "network",
        "Wazuh-only (host logs)": "host",
        "Correlated (fused)": "both",
    }
    rows: list[dict[str, Any]] = []
    for name, mode in configs.items():
        incidents = 0
        events = 0
        mttds: list[float] = []
        for j, c in enumerate(camps):
            sub = labeled[labeled["matched_idx"] == j]
            if mode == "network":
                layer = sub[sub["source_layer"] == "network"]
            elif mode == "host":
                layer = sub[sub["source_layer"] == "host"]
            else:
                layer = sub
            if layer.empty:
                continue
            incidents += 1
            count = _detected_count(layer) if mode == "both" else len(layer)
            events += min(count, c["malicious_attempts"]) if c["malicious_attempts"] else count
            if pd.notna(c["start"]):
                mttds.append((layer["timestamp"].min() - c["start"]).total_seconds())
        rows.append(
            {
                "configuration": name,
                "incidents_detected": incidents,
                "total_incidents": total_incidents,
                "incident_detection_rate": (
                    (incidents / total_incidents) if total_incidents else 0.0
                ),
                "events_detected": events,
                "total_events": total_events,
                "event_recall": (events / total_events) if total_events else 0.0,
                "mean_mttd_s": round(float(pd.Series(mttds).mean()), 1) if mttds else None,
            }
        )
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- #
# Correlation value: alert→incident reduction + single-source blind spots
# --------------------------------------------------------------------------- #
def correlation_value(df: pd.DataFrame, ground_truth: dict[str, Any]) -> dict[str, Any]:
    """
    Quantify the operational value of correlating the two telemetry sources:

      * **alert_to_incident_ratio** — how many raw alerts collapse into a single
        incident (the alert-fatigue reduction). An incident is one attack
        campaign (for true positives) or one distinct source IP (for benign
        false-positive noise).
      * **multi_source_incidents**  — incidents confirmed by *both* layers
        (higher-fidelity detections).
      * **missed_by_host_only / missed_by_network_only** — incidents a
        single-source SOC would have missed entirely but the correlated view
        catches (the coverage the integration adds).
    """
    base = {
        "total_alerts": 0,
        "num_incidents": 0,
        "true_incidents": 0,
        "fp_incidents": 0,
        "alert_to_incident_ratio": 0.0,
        "detected_by_suricata": 0,
        "detected_by_wazuh": 0,
        "detected_by_correlated": 0,
        "multi_source_incidents": 0,
        "missed_by_host_only": 0,
        "missed_by_network_only": 0,
    }
    if df.empty or not ground_truth:
        return base

    labeled = label_alerts(df, ground_truth)
    camps = _campaigns(ground_truth)
    total_alerts = len(labeled)

    matched = labeled[labeled["matched_idx"] >= 0]
    unmatched = labeled[labeled["matched_idx"] < 0]
    true_incidents = matched["matched_idx"].nunique()
    fp_incidents = unmatched["src_ip"].dropna().nunique()
    num_incidents = int(true_incidents + fp_incidents)

    by_net = by_host = by_corr = both = 0
    for j in range(len(camps)):
        sub = matched[matched["matched_idx"] == j]
        if sub.empty:
            continue
        net = bool((sub["source_layer"] == "network").any())
        host = bool((sub["source_layer"] == "host").any())
        by_net += net
        by_host += host
        by_corr += net or host
        both += net and host

    return {
        "total_alerts": total_alerts,
        "num_incidents": num_incidents,
        "true_incidents": int(true_incidents),
        "fp_incidents": int(fp_incidents),
        "alert_to_incident_ratio": round(total_alerts / num_incidents, 1) if num_incidents else 0.0,
        "detected_by_suricata": int(by_net),
        "detected_by_wazuh": int(by_host),
        "detected_by_correlated": int(by_corr),
        "multi_source_incidents": int(both),
        "missed_by_host_only": int(by_corr - by_host),
        "missed_by_network_only": int(by_corr - by_net),
    }


# --------------------------------------------------------------------------- #
# Noisy-rule analysis — which signatures generate the most false positives
# (the alert-fatigue lens: a few rules usually dominate the FP volume).
# --------------------------------------------------------------------------- #
def noisy_rules(df: pd.DataFrame, ground_truth: dict[str, Any], *, top: int = 15) -> pd.DataFrame:
    """Rank signatures by false-positive volume (FP = alert matching no campaign).

    Uses the same data-driven TP/FP rule as the confusion matrix (source IP + time
    window), so the ranking is consistent with every other metric. Returns one row
    per signature: total alerts, false positives, and the per-rule FP rate.
    """
    cols = ["signature", "alerts", "false_positives", "fp_rate"]
    if df.empty or not ground_truth or "signature" not in df:
        return pd.DataFrame(columns=cols)

    labeled = label_alerts(df, ground_truth)
    labeled = labeled.assign(is_fp=(labeled["matched_idx"] == -1))
    grp = (
        labeled.groupby(labeled["signature"].fillna("(unknown)"))
        .agg(alerts=("is_fp", "size"), false_positives=("is_fp", "sum"))
        .reset_index()
        .rename(columns={"signature": "signature"})
    )
    grp["fp_rate"] = grp["false_positives"] / grp["alerts"].where(grp["alerts"] > 0, 1)
    grp = grp.sort_values(["false_positives", "fp_rate"], ascending=False)
    return grp.head(top).reset_index(drop=True)[cols]


# --------------------------------------------------------------------------- #
# Sensitivity analysis — how the benign-population estimate moves FPR/accuracy.
# The benign volume is the analyst's biggest assumption (a baseline-capture
# estimate), so showing the metric's response to it is a threats-to-validity tool.
# --------------------------------------------------------------------------- #
def sensitivity_analysis(
    df: pd.DataFrame, ground_truth: dict[str, Any], benign_values: list[int]
) -> pd.DataFrame:
    """Recompute accuracy/FPR/precision/F1 across a range of benign-event counts."""
    cols = ["benign_events", "accuracy", "fpr", "precision", "f1"]
    if df.empty or not ground_truth:
        return pd.DataFrame(columns=cols)
    rows: list[dict[str, Any]] = []
    for b in benign_values:
        gt = {**ground_truth, "benign": {"benign_events": int(b)}}
        m = classification_metrics(confusion_matrix(df, gt))
        rows.append(
            {
                "benign_events": int(b),
                "accuracy": m["accuracy"],
                "fpr": m["fpr"],
                "precision": m["precision"],
                "f1": m["f1"],
            }
        )
    return pd.DataFrame(rows, columns=cols)


def compute_all(df: pd.DataFrame, ground_truth: dict[str, Any]) -> dict[str, Any]:
    """One-call helper returning every metric bundle, all computed from ``df``."""
    cm = confusion_matrix(df, ground_truth)
    mttd_df = mttd(df, ground_truth)
    return {
        "confusion_matrix": cm,
        "classification": classification_metrics(cm),
        "per_attack": per_attack_detection(df, ground_truth),
        "mttd": mttd_df,
        "mttd_summary": mttd_summary(mttd_df),
        "config_comparison": configuration_comparison(df, ground_truth),
        "correlation_value": correlation_value(df, ground_truth),
    }
