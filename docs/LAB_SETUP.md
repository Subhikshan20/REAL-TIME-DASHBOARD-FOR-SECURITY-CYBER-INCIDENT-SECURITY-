# Lab build guide — real Suricata × Wazuh data (matches the proposal)

> **Author:** Subhikshan Rajkumar
>
> This builds the isolated virtual lab from the proposal so it produces **real**
> Suricata IDS alerts correlated by Wazuh — the data the dashboard then analyses.
> Scripts referenced here live in `lab/`. Run each on the VM named in its heading.
>
> **Ethics / legality (per the approved proposal):** everything runs in an
> **isolated host-only network** with no route to the internet or institutional
> systems. You attack **only** the lab victim you own, in line with the **Computer
> Misuse Act 1990**. Payloads are harmless (EICAR / signature triggers).

---

## 1. Topology & IP plan

Recommended **3-VM** design (simplest, still demonstrates network↔host correlation):
Suricata runs **on the Ubuntu victim**, and a Wazuh agent on the victim ships *both*
the Suricata `eve.json` and the host logs (auth, FIM, commands) to the Manager.

```
            host-only network  192.168.56.0/24  (VirtualBox vboxnet / VMware hostonly)
   ┌──────────────────────┐      ┌─────────────────────────────┐      ┌──────────────────────┐
   │ Kali attacker        │      │ Ubuntu victim               │      │ Wazuh Manager        │
   │ 192.168.56.30        │ ───► │ 192.168.56.20               │ ───► │ 192.168.56.10        │
   │ nmap/hydra/hping3/…  │      │ Suricata IDS + Wazuh agent  │      │ Manager+Indexer+Dash │
   └──────────────────────┘      │ sshd + FIM + auditd         │      │ :55000 API / :9200   │
                                 └─────────────────────────────┘      │ :443 dashboard       │
                                                                      └──────────────────────┘
```

> **Proposal-literal 4-VM variant:** add a dedicated **Suricata sensor**
> (192.168.56.15) on a promiscuous segment between Kali and victim; the victim still
> runs the Wazuh agent for host logs. The 3-VM design above is easier and reliable for
> a student lab — note the choice in your methodology.

**VM specs** (host needs the 16 GB the proposal lists):

| VM | vCPU | RAM | Disk | OS |
|----|-----:|----:|-----:|----|
| Wazuh Manager | 4 | 6–8 GB | 50 GB | Ubuntu Server 22.04 |
| Ubuntu victim (+ Suricata) | 2 | 3 GB | 25 GB | Ubuntu Server 22.04 |
| Kali attacker | 2 | 3 GB | 25 GB | Kali Linux |

**Network:** give every VM a **host-only adapter** on the same network (VirtualBox:
*File → Host Network Manager → create*, DHCP off, then set static IPs as above). Do
**not** add a NAT/bridged adapter once you start attacking — keep it isolated. (You
may temporarily enable NAT only to install packages, then remove it.)

---

## 2. Wazuh Manager VM (192.168.56.10)

Install the all-in-one Wazuh stack (Manager + Indexer + Dashboard):

```bash
# on the Manager VM
sudo bash lab/install_wazuh_manager.sh
```

It runs the official Wazuh installation assistant and prints the **admin password** at
the end — **save it**. Verify the dashboard at `https://192.168.56.10` and the API:

```bash
curl -sk -u wazuh-wui:<api-password> https://192.168.56.10:55000/security/user/authenticate
```

## 3. Ubuntu victim VM (192.168.56.20) — Suricata + Wazuh agent

```bash
# on the victim VM
sudo bash lab/install_suricata_sensor.sh 192.168.56.0/24 enp0s8   # subnet + host-only iface
sudo bash lab/install_wazuh_agent.sh 192.168.56.10                # register to the manager
```

`install_suricata_sensor.sh` installs Suricata, pulls the **Emerging Threats open**
ruleset (so the four attacks actually fire signatures), sets `HOME_NET`, binds
Suricata to the host-only interface, and confirms `eve.json` is being written.

`install_wazuh_agent.sh` installs/registers the agent and adds the Suricata
`eve.json` to what the agent forwards (see `lab/wazuh_agent_suricata_localfile.xml`),
so Suricata alerts arrive in the Manager's `wazuh-alerts-*` index **correlated with**
the victim's host logs.

Enable the host-side signals correlation needs (the script does this, listed for your
write-up): **sshd** running (brute-force auth failures), **FIM/syscheck** on web dirs
(exploit web-shell drops), and **auditd** (command execution).

**Verify integration** (the crucial check):

```bash
# generate one test alert from Kali, then on the Manager:
curl -sk -u admin:<pwd> "https://192.168.56.10:9200/wazuh-alerts-*/_search?q=data.alert.signature:*&size=1" | head
```

## 4. Kali attacker VM (192.168.56.30)

Copy `lab/run_attacks.sh` to Kali and run the four attacks against the victim:

```bash
sudo bash lab/run_attacks.sh 192.168.56.20            # target = victim
```

It executes scan → brute force → DoS → exploit/EICAR in **separate time windows**,
records the **real** attacker IP and **UTC start/end** of each, saves each tool's
output, and writes `run_manifest.json`. (Metasploit is included as a commented,
optional step.)

## 5. Turn the run into ground truth

Bring `run_manifest.json` and the tool-output files back to this repo (or run on a box
with the repo), then:

```bash
python lab/build_ground_truth.py --manifest run_manifest.json --out data/ground_truth.json
```

This derives **real** `malicious_attempts` from the nmap/hydra logs (via
`src/attack_logs.py`) and fills in the real IPs and time windows — no guesswork. Then
set `benign.benign_events` from a quiet baseline capture (see `docs/RUNBOOK.md` Step 3).

## 6. Point the dashboard at the lab

On your analysis machine (where the dashboard runs):

```bash
export WAZUH_API_URL="https://192.168.56.10:55000"
export WAZUH_API_USER="wazuh-wui"
export WAZUH_API_PASSWORD="<api-password>"
export WAZUH_INDEXER_URL="https://192.168.56.10:9200"
export WAZUH_INDEXER_USER="admin"
export WAZUH_INDEXER_PASSWORD="<admin-password>"
export WAZUH_VERIFY_SSL="false"
./run.sh
```

Pick **Live Wazuh API** → **Test connection**. (Or copy the victim's
`/var/log/suricata/eve.json` over and use the **Upload a file** source.)

**Before trusting the numbers**, run the pre-flight check:

```bash
python src/validate_run.py --source wazuh_api          # or --source suricata_eve --path eve.json
```

Then follow `docs/RUNBOOK.md` from Step 4 (read metrics → repeat for CIs → write up).

---

## Troubleshooting

| Symptom | Fix |
|--------|-----|
| No Suricata alerts | Wrong interface in `af-packet`; `ip a` to find the host-only NIC; re-run `install_suricata_sensor.sh` with it. Confirm ET rules: `sudo suricata-update list-sources`. |
| Alerts in `eve.json` but not in Wazuh | The `localfile` block isn't loaded — check `/var/ossec/etc/ossec.conf`, then `sudo systemctl restart wazuh-agent`; confirm the agent is *Active* in the dashboard. |
| Live API connection fails | Check `WAZUH_*` values, that :55000/:9200 are reachable from the analysis host, and `WAZUH_VERIFY_SSL=false` for the self-signed lab certs. |
| Brute force shows no host evidence | Ensure `sshd` is installed/running on the victim and the agent forwards `/var/log/auth.log`. |
| Metrics show "—" or 0 TP | Run `python src/validate_run.py …` — it pinpoints IP/time/timezone mismatches. |
