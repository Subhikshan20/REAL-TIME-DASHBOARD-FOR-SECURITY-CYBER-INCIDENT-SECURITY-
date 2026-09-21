# Usability Evaluation — Heuristic Analysis

**Method:** expert heuristic evaluation against Nielsen's 10 usability heuristics.
This technique needs no human participants (so no ethics approval is required,
consistent with the isolated-lab scope of the project) yet systematically surfaces
usability strengths and defects. Each defect is rated on Nielsen's 0–4 severity
scale (0 = not a problem · 1 = cosmetic · 2 = minor · 3 = major · 4 = catastrophic).

Evaluator: Subhikshan Rajkumar. Subject: the Suricata × Wazuh SOC dashboard.

---

## Summary of findings

| # | Heuristic | Compliance | Worst open defect (severity) |
|---|-----------|------------|------------------------------|
| 1 | Visibility of system status | Strong | Long benchmark run lacks per-step progress (1) |
| 2 | Match with the real world | Strong | — |
| 3 | User control & freedom | Strong | — (resets are confirmed & reversible) |
| 4 | Consistency & standards | Strong | — |
| 5 | Error prevention | Strong | — (destructive actions gated by Yes/No) |
| 6 | Recognition over recall | Strong | Env-var-only credentials must be recalled (2) |
| 7 | Flexibility & efficiency | Good | No saved filter presets (2) |
| 8 | Aesthetic & minimalist design | Strong | — |
| 9 | Error recovery | Strong | — |
| 10 | Help & documentation | Strong | — |

No severity-3 or -4 defects were found. Remaining issues are minor/cosmetic.

---

## Heuristic-by-heuristic analysis

### 1. Visibility of system status
**Met.** A header status strip always shows the live source, alert count, **threat
posture** chip (colour-coded), detection accuracy and last-updated time. Long
operations show spinners ("Generating mock dataset…", "Benchmarking pipeline…")
and completed actions raise a toast. Auto-refresh visibly re-runs on its interval.
*Defect (severity 1):* the performance benchmark runs as a single spinner with no
incremental progress; acceptable as it completes in a few seconds.

### 2. Match between the system and the real world
**Met.** Terminology is the analyst's own — *incidents, triage, MITRE ATT&CK,
MTTD, false-positive rate, severity*. Attack categories (Scan / Brute Force / DoS /
Exploit Delivery) and signatures use real Suricata/Emerging-Threats names. Times
are shown in UTC, matching SIEM convention.

### 3. User control and freedom
**Met.** Clear "exits": **🗑️ Reset data** (empties to 0 alerts) and **♻️ Reset
dashboard** (full fresh start) are separated and **each requires a Yes/No
confirmation**. Filters can be cleared; the data source can be switched at any time;
auto-refresh can be toggled off. Uploaded files are removable via reset.

### 4. Consistency and standards
**Met.** A single design system (`theme.py`) drives every surface; the same KPI
cards, themed tables and Plotly template recur across tabs. Buttons, inputs and
charts all follow the active Light/Dark/System theme. Iconography is consistent
(🔄 refresh, 🎲 regenerate, ♻️/🗑️ reset, ⬇️ export).

### 5. Error prevention
**Met.** Destructive actions are confirmation-gated. Credentials are **never typed
into the UI** (read only from environment variables), preventing accidental
exposure. Uploads are validated by type and parsed defensively (malformed records
skipped, not fatal). The pre-flight `validate_run.py` catches ground-truth/stream
mismatches *before* a run is interpreted.

### 6. Recognition rather than recall
**Mostly met.** All controls are visible in the sidebar; `help=` tooltips explain
each option in place; the About tab lists every tab's purpose and the metric
definitions, so nothing must be memorised.
*Defect (severity 2):* live-API credentials are configured only via environment
variables, which the user must recall/prepare outside the UI. Mitigation: the
connection panel shows exactly which variables are set/missing and documents them.

### 7. Flexibility and efficiency of use
**Good.** Power features coexist with defaults: incremental *tailing* for large
eve.json, multi-run evaluation, CSV/Markdown/PDF export, and an on-demand
benchmark. Preferences (theme, source, window) persist across sessions.
*Defect (severity 2):* there is no way to save a named **filter preset**; analysts
re-apply severity/decoder filters each session. Candidate future enhancement.

### 8. Aesthetic and minimalist design
**Met.** Information is tiered: a compact KPI row first, then tabs that each own one
concern. The colour-blind-safe Okabe–Ito palette avoids decorative clutter, and the
threat posture is a single subtle chip rather than a noisy banner.

### 9. Help users recognise, diagnose and recover from errors
**Met.** Errors are surfaced in plain language, not stack traces: a failed webhook
or API test returns a readable message; an unreadable/empty capture shows guidance
("enable GeoIP enrichment…", "Upload a file to begin"); PDF export degrades to a
caption if reportlab is unavailable while keeping Markdown export working.

### 10. Help and documentation
**Met.** In-product: per-control tooltips, an About tab, and the "How these metrics
are computed" expander. Out-of-product: `README.md` (setup), `METHODOLOGY.md`
(definitions, labelling, limitations), `RUNBOOK.md` (end-to-end lab workflow) and
`LAB_SETUP.md` (building the VM lab).

---

## Prioritised recommendations
1. **(Sev 2)** Add saveable filter presets for repeat triage workflows.
2. **(Sev 2)** Offer an in-UI helper that writes the `WAZUH_*` variables to the
   environment/secrets file, reducing reliance on out-of-band recall.
3. **(Sev 1)** Show incremental progress for the benchmark sweep.

These are enhancements, not blockers: the evaluation found **no major or
catastrophic usability defects**, indicating the interface is fit for its intended
SOC-analyst audience.
