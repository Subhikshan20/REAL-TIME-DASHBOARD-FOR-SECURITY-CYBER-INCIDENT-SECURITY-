# Related Work & Positioning

This note positions the project against the SOC tooling a practitioner would
otherwise reach for. It feeds the dissertation's **Literature Review** (what
exists) and **Discussion** (what this work adds). The contribution is *not* a new
detector — Suricata and Wazuh do the detecting — but an **objective, reproducible
evaluation layer** that fuses their outputs and measures detection quality with
scientific rigour.

---

## Comparison

| Capability | Stock **Wazuh** dashboard | **Kibana / ELK** SIEM view | **Splunk** ES (commercial) | **This project** |
|---|---|---|---|---|
| Network (IDS) + host (SIEM) **correlation** in one view | Partial (host-centric) | Manual (build your own) | Yes (licensed) | **Yes, purpose-built** (Suricata × Wazuh) |
| **MITRE ATT&CK** mapping with rule-vs-inferred provenance | Basic tags | Plugin-dependent | Yes | **Yes, with explicit provenance split** |
| **Objective detection metrics** (accuracy, precision/recall, FPR) vs ground truth | No | No (no labelled GT) | Limited | **Yes — computed live from a ground-truth ledger** |
| **MTTD** per layer + improvement vs single-source baseline | No | No | Partial | **Yes** |
| **3-way baseline** (network-only / host-only / correlated) | No | No | No | **Yes — quantifies correlation value** |
| **Repeated-run statistics** (mean ± 95 % CI) | No | No | No | **Yes (`experiments.py`)** |
| **False-positive / noisy-rule analysis** | Limited | Manual | Yes | **Yes (alert-fatigue lens)** |
| **Sensitivity / threats-to-validity** tooling | No | No | No | **Yes (benign-estimate sweep)** |
| **Performance benchmark** of the pipeline | No | No | — | **Yes (throughput vs volume)** |
| **Reproducibility** (one-command verify, seeded data, tests) | n/a | n/a | n/a | **Yes (`make verify`, 130 tests)** |
| Cost / openness | Open source | Open source | Commercial | **Open source, MIT** |

---

## How this differs (the contribution)

- **Evaluation, not just visualisation.** Existing dashboards *show* alerts; they do
  not tell you, against a known ground truth, how *accurate* detection was, how
  *fast* (MTTD), or how much the *correlation* added. This project makes those
  questions answerable and reproducible.
- **Quantified correlation value.** The justified network-vs-host-vs-correlated
  baseline isolates the benefit of fusion — incidents a single-source SOC would
  miss — which generic SIEM views do not surface.
- **Scientific rigour for a dissertation.** Confidence intervals, a documented
  labelling methodology, a sensitivity analysis, and a reproducible test/verify
  pipeline turn a demo into a *validated study*.

## Representative literature to cite
- Suricata IDS and the Emerging Threats ruleset (network detection).
- The Wazuh platform documentation (host-based detection, decoders, FIM).
- The **MITRE ATT&CK** framework (technique/tactic taxonomy).
- SIEM correlation and alert-fatigue literature (motivating the real-world problem).
- Detection-evaluation methodology (confusion-matrix metrics, MTTD, CIs).

> Replace the representative list with your formal citations; the comparison table
> above is the defensible positioning claim, each row demonstrable in the tool.
