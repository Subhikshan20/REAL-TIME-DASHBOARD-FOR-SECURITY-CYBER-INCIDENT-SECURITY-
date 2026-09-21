# Results & Discussion (chapter scaffold)

> ⚠️ **READ FIRST — the numbers below are _illustrative_, computed from the
> labelled *synthetic mock dataset* so you can see the exact shape of every table
> and figure. They are NOT real findings.** Run your isolated Suricata × Wazuh lab
> ([RUNBOOK.md](RUNBOOK.md)), capture real alerts + ground truth, then regenerate
> each table with the command shown beneath it and **replace the illustrative
> values**. Every figure here is produced by the same code path for mock and real
> data, so swapping the data is all that changes.

This chapter answers the four research questions defined in
[METHODOLOGY.md](METHODOLOGY.md) §0 (RQ1 efficacy · RQ2 correlation value ·
RQ3 MTTD · RQ4 reliability) and tests **H1** (correlated detection ≥ each single
source on coverage and MTTD).

---

## 1. Experimental setup (recap)

- **Lab:** isolated host-only network (Kali attacker → Ubuntu victim, Wazuh
  Manager, Suricata sensor) — see [LAB_SETUP.md](LAB_SETUP.md). No external/
  institutional connectivity; harmless payloads (e.g. EICAR); Computer Misuse Act
  1990 compliant.
- **Workload:** the four attack campaigns (Scan, Brute Force, DoS, Exploit
  Delivery) plus one host-only-detectable (evaded) brute force, over an N-run
  repetition for confidence intervals.
- **Ground truth:** measured facts only (attacker IPs, UTC windows, attempt counts
  from tool logs via `attack_logs.py`, benign population) — no result is pre-stated.
- **Pre-flight:** each capture validated with `python src/validate_run.py` before
  interpretation.

> Reproduce real runs: `python src/experiments.py -n 15` after populating
> `data/runs/run_NN/` from your captures (see [RUNBOOK.md](RUNBOOK.md) §5).

---

## 2. Results

### 2.1 RQ1 — Detection efficacy

**Table 1 — Detection performance (mean ± 95 % CI over N = 15 runs).** *Illustrative (mock).*

| Metric | Value (mean ± 95 % CI) |
|--------|------------------------|
| Accuracy | 0.991 ± 0.001 |
| Precision | 0.956 ± 0.006 |
| Recall (detection rate) | 0.918 ± 0.011 |
| F1 | 0.936 ± 0.008 |
| False-positive rate | 0.004 ± 0.000 |

**Table 2 — Per-attack detection rate (mean ± 95 % CI).** *Illustrative (mock).*

| Attack class | Detection rate |
|--------------|----------------|
| Scan | 0.913 ± 0.017 |
| Brute Force | 0.780 ± 0.034 |
| DoS | 0.956 ± 0.009 |
| Exploit Delivery | 0.834 ± 0.039 |

**Figure 1 — Confusion matrix (single representative run).** TP = 835, FP = 30,
TN = 7649, FN = 67. *(Detection Metrics tab → confusion-matrix figure.)*

> Reproduce: Detection Metrics tab for a single run; `experiments.py -n 15` for the
> CI columns.

### 2.2 RQ2 — Correlation value

**Table 3 — Detection-configuration comparison (single run).** *Illustrative (mock).*

| Configuration | Incident detection rate | Event recall | Mean MTTD (s) |
|---------------|-------------------------|--------------|---------------|
| Suricata-only (network) | 0.89 | 0.90 | 23.6 |
| Wazuh-only (host logs) | 0.56 | 0.14 | 51.6 |
| **Correlated (fused)** | **1.00** | **0.93** | **23.7** |

**Correlation-value metrics** *(illustrative, mock):* incidents detected by
correlation = 9/9; **missed by network-only = 1** (the evaded host-only brute
force); **missed by host-only = 4** (network-only scan/DoS); alert→incident
reduction ratio ≈ 57:1.

> The correlated configuration **strictly dominates** each single source on
> incident coverage — direct support for **H1**. *(Evaluation tab.)*

### 2.3 RQ3 — Operational MTTD

**Table 4 — Mean Time To Detect by layer.** *Illustrative (mock).*

| Layer | Mean MTTD (s) |
|-------|---------------|
| Wazuh-only (host) baseline | 51.6 |
| Suricata-only (network) | 23.6 |
| **Correlated** | **29.1 ± 1.1** |
| **MTTD improvement vs host-only baseline** | **36.7 % ± 2.7 %** |

> Where host logs never fire (Scan, DoS), the attack is detectable *only* via the
> network/correlated path — reported explicitly rather than as a misleading number.

### 2.4 RQ4 — Reliability

All RQ1–RQ3 figures are reported as **mean ± 95 % CI (Student's t)** over N
independent runs (Tables 1, 2, 4). Narrow intervals (e.g. accuracy ± 0.001)
indicate the pipeline is **statistically stable**, allowing H0 to be assessed
rather than asserted. *(Reproduce: `experiments.py -n 15`.)*

### 2.5 Performance / scalability (RQ: real-time feasibility)

**Table 5 — Pipeline throughput vs alert volume.** *Measured on the dev host;
reproduce with `python src/benchmark.py` (writes `docs/benchmark_results.csv`).*

| Alerts | Normalise (ms) | Metrics (ms) | Total (ms) | Throughput (alerts/s) |
|--------|----------------|--------------|------------|-----------------------|
| 10,000 | 70 | 56 | 126 | ~79,000 |
| 50,000 | 360 | 57 | 418 | ~120,000 |
| 100,000 | 748 | 58 | 806 | ~124,000 |

Normalisation scales linearly with volume while metric computation is
near-constant (vectorised window matching), so the dashboard sustains
six-figure-per-second throughput — substantiating the "real-time" claim.

### 2.6 Sensitivity of FPR/accuracy to the benign estimate

The benign population is an *estimated* baseline-capture count, so its effect on
the headline metrics is reported (Detection Metrics tab → sensitivity chart). As
the assumed benign volume rises with FP count fixed, **FPR falls and accuracy
rises monotonically**, and the operating point is robust within a wide band around
the chosen estimate — see Threats to Validity (§3.4).

---

## 3. Discussion

### 3.1 Interpretation
The correlated pipeline meets **H1**: it detects every incident in the workload
(incident detection rate = 1.00) versus 0.89 (network-only) and 0.56 (host-only),
while matching the network sensor's MTTD. The value of correlation is therefore
**coverage** (catching incidents a single source misses) *and* **confidence**
(multi-source corroboration), not merely speed.

### 3.2 Value against the real-world problem (alert fatigue)
The alert→incident reduction (~57:1) and the **noisiest-rules analysis** (Detection
Metrics tab) show how the tool addresses the framed real-world problem: a small set
of signatures dominates false-positive volume, and grouping alerts into incidents
collapses thousands of raw alerts into a handful of triage items.

### 3.3 Comparison to related work
See [RELATED_WORK.md](RELATED_WORK.md): unlike the stock Wazuh dashboard or a
generic Kibana/ELK view, this tool adds an *objective, ground-truth-based
evaluation* (confusion matrix, FPR, MTTD) with *repeated-run confidence intervals*
and an explicit *network-vs-host-vs-correlated* baseline — the methodological
contributions of the project.

### 3.4 Threats to validity
- **Benign-population estimate** (biggest assumption): mitigated by the sensitivity
  analysis (§2.6) showing the operating point is stable across a wide band.
- **Alert ≠ attempt**: aggregated detections (e.g. a SYN flood = one alert for many
  packets) are why *incident-level* detection is the headline metric; event recall
  is reported per layer for transparency.
- **Synthetic-vs-real & lab-vs-production**: see §5.

### 3.5 Limitations & future work
Scoped to four attack classes in a controlled lab; offline threat-intel; no
encrypted-payload deep inspection. Future work: live evaluation under production
traffic, additional attack classes, and ML-assisted FP suppression building on the
noisy-rule analysis.

---

## 4. RQ → evidence traceability (Tier-3 map)

| Research question | Hypothesis | Evidence (this chapter) | Tool location |
|-------------------|------------|--------------------------|---------------|
| RQ1 — Detection efficacy | — | Tables 1–2, Figure 1 | Detection Metrics tab |
| RQ2 — Correlation value | H1 | Table 3 + correlation-value metrics | Evaluation tab |
| RQ3 — Operational MTTD | H1 | Table 4 | Detection Metrics (MTTD) |
| RQ4 — Reliability | H0/H1 | mean ± 95 % CI on all tables | `experiments.py` |
| Real-time feasibility | — | Table 5 | About → benchmark / `benchmark.py` |
| Threats to validity | — | §2.6 sensitivity, §3.4 | Detection Metrics → sensitivity |
| Usability | — | heuristic evaluation | [USABILITY_EVALUATION.md](USABILITY_EVALUATION.md) |

---

## 5. Deployment & lab-vs-production caveats

- Results are obtained in an **isolated lab**; production traffic is noisier and
  more diverse, so absolute FPR/accuracy will differ — the *methodology* (objective,
  ground-truth-based, with CIs) transfers; the *numbers* are lab-specific.
- The benign volume in production should come from a measured baseline window, not
  an estimate; the sensitivity analysis quantifies the resulting uncertainty.
- TLS verification is disabled for the lab's self-signed certs; production
  deployments must set `WAZUH_VERIFY_SSL=true` with a proper CA bundle.
- The container runs as a non-root user; enrichment stays offline unless explicitly
  enabled. See [README.md](../README.md) §8 for the full configuration surface.
