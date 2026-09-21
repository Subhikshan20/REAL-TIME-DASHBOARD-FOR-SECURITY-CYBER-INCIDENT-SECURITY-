"""Tests for attack classification (data_processor.classify_attack)."""

import data_processor as dp


def _alert(signature="", groups=None, mitre_ids=None, category=""):
    """Build a minimal canonical alert for classification tests."""
    return {
        "rule": {
            "description": signature,
            "groups": groups or [],
            "mitre": {"id": mitre_ids or [], "tactic": [], "technique": []},
        },
        "data": {"alert": {"signature": signature, "category": category}},
    }


def test_scan_signature():
    a = _alert(signature="ET SCAN Nmap -sS window 1024", groups=["ids", "suricata"])
    assert dp.classify_attack(a) == "Scan"


def test_bruteforce_by_group():
    a = _alert(signature="sshd: authentication failure", groups=["sshd", "brute_force"])
    assert dp.classify_attack(a) == "Brute Force"


def test_dos_signature():
    a = _alert(signature="ET DOS Possible SYN Flood Inbound", groups=["dos"])
    assert dp.classify_attack(a) == "DoS"


def test_exploit_by_mitre_id():
    a = _alert(signature="generic web request", mitre_ids=["T1190"])
    assert dp.classify_attack(a) == "Exploit Delivery"


def test_exploit_log4j_keyword():
    a = _alert(signature="ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)")
    assert dp.classify_attack(a) == "Exploit Delivery"


def test_benign_is_other():
    a = _alert(signature="ET POLICY Self Signed SSL Certificate", groups=["policy"])
    assert dp.classify_attack(a) == "Other"


def test_priority_specific_beats_scan():
    # Has both a 'scan' keyword and a brute-force group -> Brute Force wins.
    a = _alert(signature="SSH scan / bruteforce tool", groups=["brute_force"])
    assert dp.classify_attack(a) == "Brute Force"
