# Runbook — From your lab to dissertation results

This is the practical, end-to-end workflow for turning your **real** Suricata→Wazuh
lab into measured results in the dashboard, then into your dissertation. It assumes
the dashboard runs (`./run.sh` → http://localhost:8501) and your lab is built.

> **Scope & ethics (per the approved proposal):** every command below runs **only**
> inside your **isolated, host-only virtual lab** (Kali attacker → Ubuntu victim,
> Wazuh Manager, Suricata sensor) with **no connection to public or institutional
> networks**. Attack only hosts you own and control, in line with the **Computer
> Misuse Act 1990**. Payloads are harmless (e.g. the **EICAR** test string); no real
> systems or third parties are involved.

Workflow at a glance:

```
Step 1  Launch the 4 attacks ─► Step 2  Get the alerts into the dashboard
        (record IP + UTC times)        (Live API  or  upload eve.json)
                                              │
Step 4  Read the metrics  ◄─ Step 3  Record ground truth (data/ground_truth.json)
        │
Step 5  Repeat N times for 95% CIs  ─►  Step 6  Write it up
```

---

## Step 1 — Launch the four attacks

Run each attack from your attacker box against a lab target. **For each one, note
two things you'll need in Step 3:** the **attacker source IP** and the **start/end
time in UTC** (`date -u` before and after). Save each tool's output to a file — the
parser in `src/attack_logs.py` can read the exact attempt counts from it.

Replace `TARGET` with your lab victim IP.

**1. Scan / reconnaissance**
```bash
date -u                                   # note start time
nmap -sS -sV -p- -T4 TARGET | tee nmap_scan.txt
date -u                                   # note end time
```

**2. Brute force (SSH)** — fires both the network signature *and* host `sshd` auth failures:
```bash
date -u
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET | tee hydra_ssh.txt
date -u
```

**3. Denial of service (SYN flood)**:
```bash
date -u
sudo hping3 -S --flood -p 80 TARGET       # Ctrl-C to stop after ~1–2 min
date -u
# (or, application-layer:  slowhttptest -c 500 -H -u http://TARGET/)
```

**4. Exploit delivery & malware characteristics** — you only need to make the IDS
signature *fire*; you do **not** need a vulnerable target or a working RCE. Sending
the malicious pattern is enough to evaluate detection:
```bash
date -u
# Log4Shell pattern in a header (triggers the ET EXPLOIT log4j signature):
curl -s "http://TARGET/" -H 'User-Agent: ${jndi:ldap://127.0.0.1/a}' -o /dev/null
# SQL injection pattern:
curl -s "http://TARGET/?id=1%27%20OR%20%271%27=%271" -o /dev/null
# Malware characteristic — fetch the harmless EICAR test file across the wire
# (fires AV/IDS malware signatures without any real malware):
curl -s "http://TARGET/eicar.com" -o /dev/null
date -u
```
*Metasploit option (as listed in the proposal):* from Kali you can instead deliver a
known exploit module against the Ubuntu victim, e.g. `msfconsole` →
`use exploit/multi/http/...` → set `RHOSTS TARGET` → `run`. Keep it to your lab host
only; the goal is to generate detectable exploit traffic, not to cause harm.

Keep the attacks in **separate, non-overlapping time windows** so each maps cleanly
to one ground-truth campaign.

---

## Step 2 — Get the alerts into the dashboard

Pick whichever matches your setup (sidebar → **Data source**):

- **Live Wazuh API** *(best — real-time)*. Export your credentials, then choose
  *Live Wazuh API* and click **Test connection**:
  ```bash
  export WAZUH_API_URL="https://MANAGER_IP:55000"
  export WAZUH_API_USER="wazuh-wui"
  export WAZUH_API_PASSWORD="••••••••"
  export WAZUH_INDEXER_URL="https://INDEXER_IP:9200"
  export WAZUH_INDEXER_USER="admin"
  export WAZUH_INDEXER_PASSWORD="••••••••"
  export WAZUH_VERIFY_SSL="false"        # lab self-signed certs
  ./run.sh
  ```
- **Upload a file** — copy the sensor's `eve.json` to your machine and drag it into
  the *Suricata eve.json → Upload a file* box. (Or upload a Wazuh alerts export.)
- **Server file path** — if the dashboard runs on the sensor, point *Suricata
  eve.json → Server file path* at `/var/log/suricata/eve.json` and tick **Tail**
  for live updates.

Set the **Look-back window** wide enough to cover all four attacks.

---

## Step 3 — Record ground truth (so metrics compute)

Accuracy / FPR / MTTD show "—" until the dashboard knows what you actually did.
Tell it, once, in `data/ground_truth.json`.

1. Copy the template:
   ```bash
   cp docs/ground_truth.example.json data/ground_truth.json
   ```
2. For each campaign, fill in the **attacker IP** and the **UTC start/end** you noted
   in Step 1.
3. Fill in `malicious_attempts`. Let the tool output give you the exact number
   instead of guessing:
   ```bash
   .venv/bin/python - <<'PY'
   import sys; sys.path.insert(0, "src")
   import attack_logs
   print("nmap :", attack_logs.parse_nmap(open("nmap_scan.txt").read())["attempts"])
   print("hydra:", attack_logs.parse_hydra(open("hydra_ssh.txt").read())["attempts"])
   PY
   ```
4. Set `benign.benign_events` — the size of your **benign (negative) population**
   during the window. Practical method: run a **quiet baseline** (normal traffic,
   no attacks) for the same duration and count the events/flows observed; use that
   count. State the method in your threats-to-validity. (This value scales TN/FPR.)

> Working with real data? **Don't click 🎲 Regenerate** — it overwrites
> `data/ground_truth.json` with mock facts. Regenerate only in Mock mode.

5. **Pre-flight check before you trust the numbers.** The #1 reason a real run shows
   "—" or 0 true positives is a ground-truth/stream mismatch (wrong attacker IP, a
   timezone-shifted window, empty benign count). Verify the capture lines up first:
   ```bash
   .venv/bin/python src/validate_run.py --source suricata_eve --path /path/to/eve.json
   # or:  make validate SOURCE=wazuh_export PATH_=alerts.json
   ```
   It reports, per campaign, how many alerts fall in the window and flags any with
   zero — fix those before interpreting results.

Click **🔄 Refresh**. Every metric now reflects your real run.

How the matching works (already documented in [METHODOLOGY.md](METHODOLOGY.md)):
an alert is a **True Positive** when its `src_ip` + timestamp fall inside a campaign
window, a **False Positive** otherwise; **MTTD** per layer = first matching alert −
`start_time`.

---

## Step 4 — Read the metrics

- **Detection Metrics tab** — accuracy, precision, recall, F1, FPR, the confusion
  matrix, and MTTD per layer (Suricata vs Wazuh vs Correlated).
- **Incidents tab** — alerts grouped into incidents with risk score + triage.
- **MITRE ATT&CK tab** — technique/tactic coverage, rule-vs-inferred provenance.
- **Detection Metrics → Export** — one-click **Markdown + PDF** report of the run.

---

## Step 5 — Repeat for statistical confidence (95% CI)

One run is a single data point. For confidence intervals, repeat the **whole Step 1
attack sequence** N times (e.g. 10–15), saving each capture as its own run folder:

```
data/runs/run_01/wazuh_alerts.json   + run_01/ground_truth.json
data/runs/run_02/wazuh_alerts.json   + run_02/ground_truth.json
...
```

For each run, export the alerts (Alert Explorer → CSV won't do — use a Wazuh export
or copy the API/eve capture as `wazuh_alerts.json`) and drop in that run's
`ground_truth.json`. The **Evaluation (multi-run)** tab then reports every metric as
**mean ± 95% CI** (Student's t), the 3-way configuration comparison, and the
correlation-value metrics.

> The built-in `python src/experiments.py -n 15` generates runs from the *mock*
> generator — perfect for demonstrating the CI methodology, but for real findings
> populate `data/runs/run_NN/` from your actual captures as above.

---

## Step 6 — Map outputs to your dissertation

| Dissertation section | What to pull from the tool |
|----------------------|----------------------------|
| **Methodology** | [METHODOLOGY.md](METHODOLOGY.md) (RQs, labelling, metric formulas, risk score, baseline justification) + this runbook (data capture procedure). |
| **System / Implementation** | `docs/architecture.svg`, the module table in the README, the canonical-schema ingestion design. |
| **Results — detection performance** | Accuracy / Precision / Recall / F1 / FPR table; confusion matrix figure (Detection Metrics tab). |
| **Results — timeliness** | MTTD per layer + MTTD improvement (correlated vs host-only baseline). |
| **Results — value of correlation** | Evaluation tab: 3-way comparison table + correlation-value metrics (incidents a single-source SOC would miss). |
| **Results — robustness** | The multi-run mean ± 95% CI table. |
| **Discussion / threats to validity** | METHODOLOGY.md limitations + your `benign_events` estimation method + lab-vs-production caveats. |

### Results tables to fill (copy into your report)

**Table X — Detection performance (mean ± 95% CI over N runs)**

| Metric | Value (mean ± 95% CI) |
|--------|-----------------------|
| Accuracy | … |
| Precision | … |
| Recall (detection rate) | … |
| F1 | … |
| False-positive rate | … |

**Table Y — Detection configuration comparison**

| Configuration | Incidents detected | Event recall | Mean MTTD |
|---------------|--------------------|--------------|-----------|
| Suricata-only (network) | … | … | … |
| Wazuh-only (host logs) | … | … | … |
| Correlated (fused) | … | … | … |

**Suggested figure captions**
- *"Figure N. Confusion matrix for correlated detection across the four attack
  campaigns (N runs)."*
- *"Figure N. Mean time to detect by sensor layer; correlation reduces MTTD by X%
  relative to the host-only baseline."*
- *"Figure N. Incident-detection coverage by configuration, showing the encrypted
  brute-force incident detected only via correlated host telemetry."*
