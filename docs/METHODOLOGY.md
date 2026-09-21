# Methodology, Labelling & Limitations

This document records how the dashboard turns raw alerts into the objective
metrics it reports, the assumptions behind the ground-truth labelling, the
justified detection baseline, the correlation-value metrics, and the
repeated-run statistical procedure. It is written to be cited directly in the
dissertation's methodology and threats-to-validity sections.

---

## 0. Research questions & hypotheses

The tool is built to answer:

- **RQ1 — Detection efficacy.** With what accuracy, false-positive rate and recall
  does the correlated Suricata × Wazuh pipeline detect the four attack classes
  (scan, brute force, DoS, exploit delivery)? *(→ Detection Metrics tab)*
- **RQ2 — Correlation value.** Does fusing network IDS with host telemetry detect
  more incidents, faster, and with less alert fatigue than either source alone?
  *(→ Evaluation tab: 3-way comparison + correlation-value metrics)*
- **RQ3 — Operational MTTD.** What Mean-Time-To-Detect does correlation achieve,
  and what is the reduction versus a single-source baseline? *(→ MTTD per layer)*
- **RQ4 — Reliability.** Are the results statistically stable across repeated
  runs (reported as mean ± 95% CI)? *(→ experiments.py)*

**H1:** correlated detection ≥ each single source on incident coverage and MTTD.
**H0:** no significant difference. Repeated runs + confidence intervals let H0 be
assessed rather than asserted.

---

## 1. Data sources and the canonical schema

All inputs are normalised to a single canonical alert schema (`ingest.py`):

| Source | What it is |
|---|---|
| Live Wazuh API | Correlated alerts from the Wazuh Indexer (`wazuh-alerts-*`). |
| Suricata `eve.json` | Raw IDS `alert` events, wrapped exactly as Wazuh wraps them. |
| Wazuh export | Exported alert documents (JSON array or NDJSON). |
| Mock | A synthetic, *labelled* stream used **only** for pre-lab development. |

The same processing, classification, metric and visualisation code runs for
every source, so results obtained on the mock stream are produced by the
identical pipeline that will run on real lab data.

> **On synthetic data:** the mock stream is synthetic by necessity (it exists so
> the tool can be built before the lab is live). It is never blended into a
> "live" view, and **no metric value is stored** in it — every figure is
> recomputed from the stream. The variance seen across mock runs is illustrative
> of the *machinery*; the dissertation's reported numbers must come from repeated
> **real** lab runs.

---

## 2. Ground-truth labelling method

Objective detection metrics require knowing which events were truly malicious.
In a controlled lab the analyst knows this, because they launched the attacks.
The ground-truth file (`data/ground_truth.json`) therefore records **only
measured facts**, never results:

```json
{
  "campaigns": [
    { "attack_type": "...", "source_ip": "...",
      "start_time": "...", "end_time": "...", "malicious_attempts": N }
  ],
  "benign": { "benign_events": M }
}
```

**Labelling rule.** An alert is labelled a **True Positive (TP)** when its
`src_ip` matches a campaign's attacker IP *and* its timestamp lies within that
campaign's `[start_time, end_time]` window. An alert matching no campaign is a
**False Positive (FP)**. From the measured totals:

- **False Negatives (FN)** = `malicious_attempts − detected`
- **True Negatives (TN)** = `benign_events − FP`

**Detection counting granularity.** "Detected" is counted at the network-flow
granularity (one Suricata alert ≈ one detected malicious flow); if a campaign
produced no network alerts, host-log alerts are counted instead. This avoids
double-counting the same malicious event when both a network signature and a
host-log rule fire for it.

### Assumptions and edge cases (threats to validity)

1. **IP + window attribution.** Assumes attacker IPs are known and not shared
   with benign hosts during the window. NAT/shared egress IPs or benign traffic
   from an attacker IP inside the window would be mis-labelled. Mitigation: use
   dedicated attacker hosts in the lab; record exact windows.
2. **Spoofed / rotating source IPs** (common in DoS) would break IP attribution.
   Mitigation: for such attacks, attribute by destination + signature + window,
   or by the attack tool's own logs.
3. **Alert ≠ attempt.** Detection counting approximates one alert per malicious
   event. Aggregating rules (e.g. one brute-force alert after N failures) can
   under-count detections relative to attempts. Mitigation: cross-check against
   the attack tool's output (hydra/nmap/metasploit) for attempt-level truth.
4. **Benign volume is analyst-supplied.** TN and FPR depend on a correct
   `benign_events` count; measure it from the traffic generator / capture stats.

---

## 3. Metric definitions

All computed in `metrics.py` from the labelled stream:

- **Accuracy** = (TP + TN) / (TP + TN + FP + FN)
- **Precision** = TP / (TP + FP)
- **Recall / Detection Rate** = TP / (TP + FN)
- **F1** = 2·Precision·Recall / (Precision + Recall)
- **False Positive Rate (FPR)** = FP / (FP + TN)
- **MTTD (per layer)** = first matched alert of that layer − `start_time`,
  measured directly from timestamps.

---

## 4. Justified detection baseline (3-way comparison)

The thesis is that **correlating** the Suricata network sensor with Wazuh host
telemetry outperforms either source alone. To make this measurable rather than
assumed, `configuration_comparison()` evaluates the *same* alert stream under
three configurations:

| Configuration | Alerts considered |
|---|---|
| **Suricata-only (network)** | network-layer alerts only |
| **Wazuh-only (host logs)** | host-log alerts only (a traditional log-based SIEM) |
| **Correlated (fused)** | both layers — this dashboard |

For each it reports **incident detection rate**, **event recall** and **mean
MTTD**. The correlated configuration is therefore benchmarked against two
single-source baselines drawn from the identical data, so any improvement is a
direct, fair comparison rather than a hard-coded reference value.

> **Recommended extension for the write-up:** also benchmark against the
> *out-of-the-box* Wazuh/Kibana dashboard (the practitioner status quo) as an
> external control group.

---

## 5. Correlation-value metrics

`correlation_value()` quantifies the operational benefit of fusing the sources:

- **Alert → incident ratio** — raw alerts collapsed per incident (an incident is
  one attack campaign for true positives, or one distinct source IP for benign
  noise). This is the **alert-fatigue reduction**: a high ratio means analysts
  triage incidents, not thousands of raw alerts.
- **Multi-source confirmed incidents** — incidents where both the network sensor
  and host logs fired, i.e. higher-fidelity, corroborated detections.
- **Incidents missed by host-only / network-only** — incidents the correlated
  view catches that a single-source SOC would miss entirely (the coverage the
  integration adds).

### Coverage vs confirmation — an important nuance

Correlation can help in up to **four distinct ways**, and they must not be
conflated in the write-up:

1. **Coverage** — catching incidents a single source would miss entirely
   (reported by *missed by host-only / network-only*).
2. **Speed** — lower MTTD (the network sensor often fires before host logs
   aggregate).
3. **Confidence** — multi-source confirmation reduces ambiguity / false alarms.
4. **Alert-fatigue** — many raw alerts collapse into few incidents.

Whether the **coverage** gain is large is *data-dependent*. If the host
telemetry only ever *corroborates* events the network sensor already detects
(host alerts are a subset of network coverage), then at the event level the
correlated recall equals the network-only recall, and correlation's value lies in
speed, confidence and fatigue rather than extra coverage. Coverage gain only
appears when at least one source detects something the other cannot — e.g. a
network-only attack (port scan, volumetric DoS) that host logs never see, **and**
a host-only event (a brute-force over an encrypted channel the IDS cannot
inspect, a local privilege escalation, a file-integrity change) that the network
sensor never sees.

The bundled lab dataset deliberately includes **both** directions (network-only
Scan/DoS and a host-only encrypted brute-force), so the correlated configuration
is strictly better than either single source at the incident level. **On real
lab data the relationship may differ** — the framework computes and reports
whatever is actually true; do not assume a coverage gain, let the repeated real
runs produce the headline numbers.

> Counting note: the correlated **event recall** dedups corroborating
> cross-layer alerts (a network alert and a host alert for the same flow count
> once) and adds host-only events as new coverage. On real data, perfect
> cross-layer event de-duplication is not generally possible, so the
> **incident-level** detection rate is the most defensible cross-source coverage
> metric; event recall is reported per layer.

---

## 5a. Incident grouping, enrichment and real-time ingestion

- **Incidents** (`incidents.py`) group alerts by (source IP, attack category) so
  analysts triage incidents, not raw alerts. Each incident carries an aggregate
  severity, the layers that fired, ATT&CK techniques, and a persisted triage
  **status** (New / Investigating / Resolved / False Positive) + note.
- **Enrichment** (`enrichment.py`) is **offline by default**: IP scope via the
  standard library and a threat-intel verdict from a local, analyst-curated
  indicator feed (`threat_intel.json`). Online lookups (AbuseIPDB/GreyNoise/…)
  are an opt-in integration point only — the dashboard never contacts external
  services on its own, so no observed data leaves the host without the operator
  deliberately wiring it up.
- **Real-time `eve.json` tailing** (`ingest.tail_suricata_eve`) reads only the
  bytes appended since the previous poll (tracking offset + size, resetting on
  rotation/truncation), so it scales to large, continuously-growing logs. A
  partial final line being written concurrently is skipped and picked up on the
  next poll. Auto-refresh uses a non-blocking Streamlit fragment timer, so the UI
  stays interactive between refreshes.

---

## 6. Repeated runs and confidence intervals

A single run is one observation and cannot support statistical claims.
`experiments.py` runs the study **N independent times** and aggregates:

- Each run's scalar metrics are computed by the identical pipeline.
- Across runs, each metric is summarised as **mean, sample standard deviation
  (ddof = 1), and a two-tailed 95% confidence interval using Student's t**
  (`mean ± t₀.₉₇₅,ₙ₋₁ · s/√n`). The t-distribution is used because lab sample
  sizes are small; for n > 30 the normal approximation (1.96) is applied.

**For the live lab:** repeat each attack script N times (≥10 recommended), export
the alerts per run, and place each run under `data/runs/run_NN/` with its
matching `ground_truth.json`. The Evaluation tab then reports mean ± 95% CI and
exports the aggregated results as CSV.

---

## 6a. Attempt-level ground truth from attack-tool logs

Rather than hand-entering `malicious_attempts`, `attack_logs.py` parses the
attacker tooling's own output for an objective count:

- **hydra** — total login attempts, read from either the verbose `N of M`
  progress lines or the `[DATA] … N login tries` banner that hydra always prints
  (so the count is recovered from default, non-verbose output too), plus the
  `[svc] host:` success lines (valid credentials).
- **nmap** — hosts scanned and open ports observed; the open-port count is the
  attempt figure used for the scan campaign (the detectable service contacts the
  dashboard clamps detections to). The raw `ports_probed` count is parsed and
  reported separately for transparency but is *not* used as the recall
  denominator, which would otherwise make scan recall meaningless.

`build_campaign_fact()` turns a tool log directly into a ground-truth campaign
entry (`ground_truth_source` records the tool), removing analyst guesswork and
strengthening the alert-vs-attempt accounting.

---

## 6b. Composite risk score

`risk.py` ranks incidents by a transparent, weighted blend rather than the raw
rule level:

```
risk = 100 · (0.40·severity + 0.25·asset_criticality
              + 0.20·threat_intel + 0.15·frequency)
```

where *severity* is the normalised max rule-level band, *asset_criticality* comes
from `assets.json` (the targeted host's business value), *threat_intel* is the
source IP's known-bad confidence (`enrichment.py`), and *frequency* is the
log-scaled alert volume. Weights are explicit and tunable.

---

## 6c. Baseline beyond single sources — external control group

The 3-way comparison benchmarks correlated detection against the two single
sources drawn from the *same* data. For an **external control group**, also run
the attacks against the practitioner status quo — the **out-of-the-box
Wazuh/Kibana dashboard with default rules** — and record, per attack, whether it
detected the campaign and its MTTD. Place those measurements in a `control`
section of `ground_truth.json` and compare against this tool's numbers in the
write-up. (This requires the live Kibana instance and is therefore documented as
methodology rather than bundled.)

---

## 7. Data dictionary (normalised alert row)

Each row of the analysis DataFrame (`data_processor.normalize_alerts`) has:

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | datetime (UTC) | Alert time. |
| `alert_id` | str | Source alert id (Wazuh id / Suricata flow id). |
| `rule_id`, `rule_level` | str, int | Wazuh/Suricata rule id and severity level. |
| `severity` | str | Band: Critical/High/Medium/Low/Unknown. |
| `description`, `signature`, `signature_category` | str | Rule + signature text. |
| `groups` | str | Rule groups / Suricata classtype tokens. |
| `agent`, `decoder`, `location` | str | Reporting agent, decoder, log source. |
| `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto` | str | 5-tuple. |
| `flow_id` | int | Suricata flow id (cross-layer correlation key). |
| `src_country` | str | GeoIP country (when enriched). |
| `attack_category` | str | Scan / Brute Force / DoS / Exploit Delivery / Other. |
| `classification_confidence` | float | 0–1 strength of the classifying signal. |
| `mitre_ids`, `mitre_tactics`, `mitre_techniques` | list | ATT&CK mapping. |
| `mitre_source` | str | `rule` (from metadata) / `inferred` / `none`. |
| `is_true_positive` | bool/None | Embedded label (mock/labelled only; metrics never read it for classification). |

---

## 8. Summary of limitations

1. Detection metrics depend on the accuracy of the analyst-supplied ground truth
   (windows, attacker IPs, attempt counts, benign volume).
2. IP+window labelling is unreliable for spoofed/shared IPs.
3. Alert-to-attempt mapping is an approximation.
4. The MITRE mapping is curated for the four studied attacks; other signatures
   fall back to inference from the classified category and should be validated.
5. Mock-data variance demonstrates the method, not the lab's true performance —
   report results from real repeated runs.
