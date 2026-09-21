# `lab/` — real Suricata × Wazuh lab kit

Scripts to stand up the proposal's virtual lab so it produces **real** data for the
dashboard. Full walkthrough: **[../docs/LAB_SETUP.md](../docs/LAB_SETUP.md)**.

| File | Run on | Purpose |
|------|--------|---------|
| `install_wazuh_manager.sh` | Wazuh Manager VM | All-in-one Wazuh (Manager + Indexer + Dashboard). |
| `install_suricata_sensor.sh` | Ubuntu victim | Suricata + ET ruleset + HOME_NET/interface + eve.json. |
| `install_wazuh_agent.sh` | Ubuntu victim | Wazuh agent; forwards eve.json **and** host logs (auth/FIM/cmd). |
| `wazuh_agent_suricata_localfile.xml` | Ubuntu victim | The `ossec.conf` snippet that ships Suricata alerts to Wazuh. |
| `run_attacks.sh` | Kali attacker | Runs scan/brute/DoS/exploit, recording real IPs + UTC windows. |
| `build_ground_truth.py` | repo host | Turns the attack run into a real `data/ground_truth.json`. |

> **Lab only.** Every attack targets your own isolated host-only victim, per the
> Computer Misuse Act 1990. Payloads are harmless (EICAR / signature triggers).
