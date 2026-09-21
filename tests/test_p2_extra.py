"""Tests for the P2 additions: attack-log parsing, assets, risk, audit, prefs, notifier."""

import pandas as pd

import assets
import attack_logs
import audit
import notifier
import prefs
import risk

HYDRA_LOG = """
[DATA] attacking ssh://10.0.0.10:22/
[ATTEMPT] target 10.0.0.10 - login "root" - pass "123456" - 1 of 1000 [child 0]
[ATTEMPT] target 10.0.0.10 - login "root" - pass "password" - 2 of 1000 [child 1]
[22][ssh] host: 10.0.0.10   login: root   password: toor
1 of 1 target successfully completed, 1 valid password found
"""

NMAP_LOG = """
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.0.0.5
Host is up (0.00040s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  closed https
"""


# --------------------------- attack_logs ---------------------------------- #
def test_parse_hydra():
    r = attack_logs.parse_hydra(HYDRA_LOG)
    assert r["attempts"] == 1000
    assert r["successes"] == 1
    assert r["credentials"][0]["login"] == "root"


def test_parse_nmap():
    r = attack_logs.parse_nmap(NMAP_LOG)
    assert r["hosts"] == 1
    assert r["open_ports"] == 2


# Default (non-verbose) tool output — what `run_attacks.sh` / the RUNBOOK actually
# produce. These guard the regression where the parsers under-counted (hydra read
# "1 of 1 target" as 1; nmap fell back to open-port count instead of ports probed).
HYDRA_LOG_DEFAULT = """
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
[DATA] max 4 tasks per 1 server, overall 4 tasks, 150 login tries (l:1/p:150), ~38 tries per task
[DATA] attacking ssh://192.168.56.20:22/
[STATUS] 183.00 tries/min, 92 tries in 00:00h, 58 to do in 00:01h, 4 active
[22][ssh] host: 192.168.56.20   login: root   password: toor
1 of 1 target successfully completed, 1 valid password found
"""

NMAP_LOG_DEFAULT = """
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.56.20
Host is up (0.00042s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
80/tcp   open  http    Apache httpd 2.4.52
3306/tcp open  mysql   MySQL 8.0.36
Nmap done: 1 IP address (1 host up) scanned in 42.13 seconds
"""


def test_parse_hydra_default_output_reads_planned_total():
    # No [ATTEMPT] lines (default run); total must come from the [DATA] banner,
    # not the "1 of 1 target" summary line.
    r = attack_logs.parse_hydra(HYDRA_LOG_DEFAULT)
    assert r["attempts"] == 150
    assert r["successes"] == 1


def test_parse_nmap_default_output_counts_ports_probed():
    # No "Scanned N ports" line; ports_probed = "Not shown" + listed ports (info),
    # while the metric attempt count stays the open ports observed (methodology).
    r = attack_logs.parse_nmap(NMAP_LOG_DEFAULT)
    assert r["open_ports"] == 3
    assert r["ports_probed"] == 65535
    assert r["attempts"] == 3


def test_parse_unsupported():
    import pytest

    with pytest.raises(ValueError):
        attack_logs.parse("metasploit", "x")


def test_build_campaign_fact_from_log():
    fact = attack_logs.build_campaign_fact(
        "Brute Force",
        "45.155.205.99",
        "2026-07-01T10:00:00+0000",
        "2026-07-01T10:10:00+0000",
        tool="hydra",
        log_text=HYDRA_LOG,
    )
    assert fact["malicious_attempts"] == 1000
    assert fact["ground_truth_source"] == "hydra"


def test_build_campaign_fact_explicit():
    fact = attack_logs.build_campaign_fact("DoS", "192.0.2.66", "s", "e", malicious_attempts=500)
    assert fact["malicious_attempts"] == 500


def test_build_campaign_fact_requires_source():
    import pytest

    with pytest.raises(ValueError):
        attack_logs.build_campaign_fact("Scan", "1.1.1.1", "s", "e")


# --------------------------- assets --------------------------------------- #
def test_load_assets_and_criticality():
    inv = assets.load_assets()  # repo-root assets.json
    assert any(a["ip"] == "10.0.0.5" for a in inv)
    idx = assets.asset_index(inv)
    assert assets.criticality_of("10.0.0.5", idx) == "critical"
    assert assets.criticality_of("8.8.8.8", idx) == "unknown"
    assert assets.criticality_weight("critical") > assets.criticality_weight("low")


def test_targeted_assets():
    import data_processor as dp

    alert = {
        "timestamp": "2026-06-27T10:00:00.000+0000",
        "id": "1",
        "agent": {"name": "suricata-sensor"},
        "rule": {
            "id": "1",
            "level": 12,
            "description": "ET EXPLOIT",
            "groups": ["ids", "exploit"],
            "mitre": {"id": ["T1190"], "tactic": [], "technique": []},
        },
        "decoder": {"name": "suricata"},
        "data": {
            "srcip": "203.0.113.7",
            "dest_ip": "10.0.0.5",
            "alert": {"signature": "ET EXPLOIT", "category": "x"},
        },
    }
    df = dp.normalize_alerts([alert])
    ta = assets.targeted_assets(df)
    assert ta.iloc[0]["dest_ip"] == "10.0.0.5"
    assert ta.iloc[0]["criticality"] == "critical"


# --------------------------- risk ----------------------------------------- #
def test_risk_score_and_band():
    high = risk.score("Critical", assets.criticality_weight("critical"), "malicious", 95, 200)
    low = risk.score("Low", assets.criticality_weight("low"), "unknown", None, 1)
    assert high > low
    assert 0 <= low <= 100 and 0 <= high <= 100
    assert risk.band(80) == "Critical"
    assert risk.band(10) == "Low"


# --------------------------- audit ---------------------------------------- #
def test_audit_roundtrip(tmp_path):
    path = str(tmp_path / "audit.log")
    audit.record("login.success", user="analyst", detail="ok", path=path)
    audit.record("export.alerts_csv", user="analyst", detail="100 rows", path=path)
    entries = audit.read_audit(path=path)
    assert len(entries) == 2
    assert entries[0]["event"] == "export.alerts_csv"  # newest first


# --------------------------- prefs ---------------------------------------- #
def test_prefs_roundtrip(tmp_path):
    path = str(tmp_path / "prefs.json")
    prefs.save_prefs(
        {
            "source_label": "Suricata eve.json",
            "window_minutes": 60,
            "auto_refresh": True,
            "interval": 30,
        },
        path=path,
    )
    loaded = prefs.load_prefs(path)
    assert loaded["source_label"] == "Suricata eve.json"
    assert loaded["window_minutes"] == 60


def test_prefs_defaults_when_missing(tmp_path):
    loaded = prefs.load_prefs(str(tmp_path / "nope.json"))
    assert loaded == prefs.DEFAULTS


# --------------------------- notifier ------------------------------------- #
def _inc_df():
    return pd.DataFrame(
        [
            {
                "severity": "Critical",
                "attack_category": "Exploit Delivery",
                "src_ip": "1.1.1.1",
                "alert_count": 10,
                "layers": "host+network",
            },
            {
                "severity": "Low",
                "attack_category": "Other",
                "src_ip": "2.2.2.2",
                "alert_count": 1,
                "layers": "network",
            },
        ]
    )


def test_critical_incidents_filter():
    crit = notifier.critical_incidents(_inc_df())
    assert len(crit) == 1
    assert crit.iloc[0]["severity"] == "Critical"


def test_build_payload():
    payload = notifier.build_payload(_inc_df(), "Mock")
    assert payload["incident_count"] == 1
    assert "critical incident" in payload["text"]


def test_summary_markdown_renders_real_emoji_dynamically():
    md = notifier.summary_markdown(_inc_df(), "Mock")
    # Real emoji + rendered markdown, not raw Slack shortcodes/syntax.
    assert "🚨" in md and "🔴" in md
    assert ":rotating_light:" not in md
    assert "**Exploit Delivery**" in md  # the one critical incident
    assert "1.1.1.1" in md and "Mock" in md
    assert "2.2.2.2" not in md  # the Low incident is excluded


def test_summary_markdown_empty_is_calm():
    empty = _inc_df().iloc[0:0]
    assert "No critical incidents" in notifier.summary_markdown(empty)


def test_send_webhook_no_url():
    ok, msg = notifier.send_webhook({"text": "hi"}, url="")
    assert ok is False


def test_send_webhook_mocked(monkeypatch):
    class FakeResp:
        status_code = 200

    monkeypatch.setattr("requests.post", lambda *a, **k: FakeResp())
    ok, msg = notifier.send_webhook({"text": "hi"}, url="https://example.test/hook")
    assert ok is True
    assert "200" in msg
