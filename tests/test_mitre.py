"""Tests for the MITRE ATT&CK mapping helpers (mitre_mapping.py)."""

import mitre_mapping as mm


def test_technique_url_top_level():
    assert mm.technique_url("T1110") == "https://attack.mitre.org/techniques/T1110/"


def test_technique_url_sub_technique():
    assert mm.technique_url("T1110.001") == "https://attack.mitre.org/techniques/T1110/001/"


def test_tactic_for_known_technique():
    assert mm.tactic_for_technique("T1110") == "Credential Access"


def test_tactic_for_sub_technique_falls_back_to_parent():
    assert mm.tactic_for_technique("T1110.001") == "Credential Access"


def test_tactic_for_unknown_is_unknown():
    assert mm.tactic_for_technique("T9999") == "Unknown"


def test_every_attack_category_has_techniques():
    for category in mm.ATTACK_CATEGORIES:
        assert category in mm.MITRE_BY_ATTACK
        assert len(mm.MITRE_BY_ATTACK[category]) >= 1


def test_technique_index_is_consistent():
    # Every technique listed under an attack must resolve in the flat index.
    for techs in mm.MITRE_BY_ATTACK.values():
        for t in techs:
            assert t["id"] in mm.TECHNIQUE_INDEX
            assert mm.TECHNIQUE_INDEX[t["id"]]["tactic"] == t["tactic"]
