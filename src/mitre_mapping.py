"""
mitre_mapping.py
================
MITRE ATT&CK reference data for the four simulated attack categories.

This module is the single source of truth that ties each high-level attack
(Scan, Brute Force, DoS, Exploit Delivery) to the specific ATT&CK techniques and
tactics the dashboard reports against. Keeping it separate means the mapping can
be cited / audited independently in the dissertation.

Reference: https://attack.mitre.org/
"""

# The four attack scenarios driven in the lab.
ATTACK_CATEGORIES = ["Scan", "Brute Force", "DoS", "Exploit Delivery"]

# Tactics laid out in MITRE kill-chain order — used to lay out the coverage
# matrix / heatmap on the MITRE tab.
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Representative ATT&CK techniques observed for each simulated attack.
# Each entry: technique id, human name, and the tactic it sits under.
MITRE_BY_ATTACK = {
    "Scan": [
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        {"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery"},
    ],
    "Brute Force": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
    ],
    "DoS": [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
        {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
    ],
    "Exploit Delivery": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
}

# A broader reference catalogue so signatures OUTSIDE the four studied attacks
# still map to ATT&CK instead of falling into an empty "Other" bucket. Names are
# the canonical ATT&CK technique names.
TECHNIQUE_CATALOGUE = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1018": ("Remote System Discovery", "Discovery"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1498": ("Network Denial of Service", "Impact"),
    "T1499": ("Endpoint Denial of Service", "Impact"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1203": ("Exploitation for Client Execution", "Execution"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1505.003": ("Web Shell", "Persistence"),
    "T1566": ("Phishing", "Initial Access"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    # Network-only blind spot for host-based SIEMs (proxy/tunnelled C2): a key
    # coverage case for IDS↔SIEM correlation noted in the literature review.
    "T1090": ("Proxy", "Command and Control"),
}

# Suricata rule `classtype` -> representative ATT&CK technique ids. Lets real
# eve.json that lacks explicit ATT&CK metadata still be mapped.
CLASSTYPE_TECHNIQUES = {
    "attempted-recon": ["T1595"],
    "network-scan": ["T1046"],
    "attempted-admin": ["T1110"],
    "attempted-user": ["T1078"],
    "web-application-attack": ["T1190"],
    "web-application-activity": ["T1190"],
    "denial-of-service": ["T1498"],
    "attempted-dos": ["T1499"],
    "shellcode-detect": ["T1203"],
    "trojan-activity": ["T1071"],
    "command-and-control": ["T1071"],
    "successful-admin": ["T1078"],
    "credential-theft": ["T1110"],
    "exploit-kit": ["T1190"],
}

# Flat lookup: technique id -> {name, tactic, attack}. Built once at import.
TECHNIQUE_INDEX = {}
for _attack, _techs in MITRE_BY_ATTACK.items():
    for _t in _techs:
        TECHNIQUE_INDEX[_t["id"]] = {
            "name": _t["name"],
            "tactic": _t["tactic"],
            "attack": _attack,
        }
# Fold in catalogue entries not already covered by the four attacks.
for _tid, (_name, _tactic) in TECHNIQUE_CATALOGUE.items():
    TECHNIQUE_INDEX.setdefault(_tid, {"name": _name, "tactic": _tactic, "attack": "Other"})


def technique_url(technique_id: str) -> str:
    """Return the canonical attack.mitre.org URL for a technique / sub-technique."""
    base = "https://attack.mitre.org/techniques/"
    if "." in technique_id:  # sub-technique, e.g. T1110.001 -> /T1110/001/
        parent, sub = technique_id.split(".", 1)
        return f"{base}{parent}/{sub}/"
    return f"{base}{technique_id}/"


def tactic_for_technique(technique_id: str) -> str:
    """Look up the tactic for a technique id, tolerating sub-techniques."""
    if technique_id in TECHNIQUE_INDEX:
        return TECHNIQUE_INDEX[technique_id]["tactic"]
    parent = technique_id.split(".", 1)[0]
    return TECHNIQUE_INDEX.get(parent, {}).get("tactic", "Unknown")


def techniques_from_classtype(classtype: str) -> list[dict[str, str]]:
    """Map a Suricata rule classtype to representative ATT&CK techniques."""
    out = []
    for tid in CLASSTYPE_TECHNIQUES.get(str(classtype).lower().strip(), []):
        info = TECHNIQUE_INDEX.get(tid, {})
        out.append(
            {"id": tid, "name": info.get("name", tid), "tactic": info.get("tactic", "Unknown")}
        )
    return out


# Broad signature/keyword -> ATT&CK technique hints, for signatures outside the
# four studied attacks (so the ATT&CK view isn't empty on real, varied eve.json).
KEYWORD_TECHNIQUES = [
    ("web shell", "T1505.003"),
    ("webshell", "T1505.003"),
    ("trojan", "T1071"),
    ("command and control", "T1071"),
    (" c2 ", "T1071"),
    ("exfil", "T1041"),
    ("phish", "T1566"),
    ("ingress tool", "T1105"),
    ("tool transfer", "T1105"),
    ("download", "T1105"),
    ("valid account", "T1078"),
    ("successful login", "T1078"),
    ("sql injection", "T1190"),
    ("rce", "T1190"),
    ("exploit", "T1190"),
    ("brute", "T1110"),
    ("login failure", "T1110"),
    ("scan", "T1595"),
    ("nmap", "T1046"),
    ("dos", "T1498"),
    ("flood", "T1498"),
    ("proxy", "T1090"),
    ("tunnel", "T1090"),
]


def _technique_dict(tid: str) -> dict[str, str]:
    info = TECHNIQUE_INDEX.get(tid, {})
    return {"id": tid, "name": info.get("name", tid), "tactic": info.get("tactic", "Unknown")}


def infer_techniques(category: str, groups, signature: str) -> list[dict[str, str]]:
    """
    Best-effort ATT&CK inference for an alert from its Suricata classtype-like
    groups and signature/category text. Returns a de-duplicated technique list
    (possibly empty for genuinely benign traffic).
    """
    found: dict[str, dict[str, str]] = {}
    for g in groups or []:
        for d in techniques_from_classtype(g):
            found[d["id"]] = d
    text = " ".join(
        [str(category), " ".join(str(g) for g in (groups or [])), str(signature)]
    ).lower()
    for kw, tid in KEYWORD_TECHNIQUES:
        if kw in text and tid not in found:
            found[tid] = _technique_dict(tid)
    return list(found.values())
