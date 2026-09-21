"""
attack_logs.py
==============
Derive **attempt-level ground truth** from the attacker's own tooling output
(hydra, nmap, …) instead of hand-entered numbers.

In a controlled lab the attack tools record exactly how many attempts they made
(hydra prints "N of M"; nmap reports hosts/ports). Parsing those logs gives an
objective ``malicious_attempts`` count for each campaign — closing the
"alert ≠ attempt" gap and removing analyst guesswork from the ground truth.

Only well-defined, regex-parseable fields are extracted; anything not present in
the output is left to the analyst rather than guessed.
"""

from __future__ import annotations

import re
from typing import Any

from logging_config import get_logger

log = get_logger("attack_logs")

SUPPORTED_TOOLS = ("hydra", "nmap")


def parse_hydra(text: str) -> dict[str, Any]:
    """
    Parse THC-hydra output.

    Returns: tool, attempts (total login tries), successes (valid credentials),
    and the recovered credential lines.
    """
    # Total planned login tries — robust to verbose *and* default hydra output:
    #  • verbose attempt lines: "... - 123 of 1000 [child 0]"  -> 1000
    #  • the [DATA] banner (always printed):  "... 1000 login tries"  -> 1000
    # The "[child" anchor avoids matching the unrelated "1 of 1 target" summary.
    of_totals = [int(m) for m in re.findall(r"\bof\s+(\d+)\s*\[child", text)]
    data_tries = [int(m) for m in re.findall(r"(\d+)\s+login tries\b", text)]
    attempt_lines = len(re.findall(r"\[ATTEMPT\]", text))
    if of_totals:
        attempts = max(of_totals)
    elif data_tries:
        attempts = max(data_tries)
    else:
        attempts = attempt_lines

    # Success lines: "[22][ssh] host: 10.0.0.10  login: root  password: toor"
    success_lines = re.findall(
        r"\[\d+\]\[\w+\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)", text
    )
    return {
        "tool": "hydra",
        "attempts": attempts,
        "successes": len(success_lines),
        "credentials": [{"host": h, "login": u, "password": p} for h, u, p in success_lines],
    }


def parse_nmap(text: str) -> dict[str, Any]:
    """
    Parse nmap normal output.

    Returns: tool, hosts (scanned), open_ports, ports_probed (informational), and
    the ground-truth ``attempts`` count. Per METHODOLOGY §2 the scan's malicious
    "events" are the **open ports observed** (the detectable service contacts),
    not the raw probe count — the dashboard clamps detections to this, so feeding
    the full 65k-probe total would make scan recall meaningless. ``ports_probed``
    is parsed accurately and reported separately for transparency.
    """
    hosts = len(re.findall(r"Nmap scan report for", text))
    open_ports = len(re.findall(r"(?m)^\d+/\w+\s+open\b", text))

    # Ports actually probed — reported for transparency only, in order of reliability:
    #  1. verbose banner:        "Scanning 10.0.0.5 [65535 ports]"
    #  2. timing/stats output:   "Scanned 65535 ports"
    #  3. default scan summary:  "Not shown: 65532 closed tcp ports" + listed ports
    scanning = [int(m) for m in re.findall(r"\[(\d+)\s+ports?\]", text)]
    scanned = re.search(r"Scanned\D+(\d+)\s+ports", text)
    not_shown = sum(int(m) for m in re.findall(r"Not shown:\s+(\d+)\s+\w+", text))
    listed_ports = len(re.findall(r"(?m)^\d+/\w+\s+(?:open|closed|filtered)\b", text))
    if scanning:
        ports_probed = max(scanning)
    elif scanned:
        ports_probed = int(scanned.group(1))
    elif not_shown:
        ports_probed = not_shown + listed_ports
    else:
        ports_probed = 0

    # Ground-truth attempt count for the metric denominator (methodology-aligned).
    attempts = open_ports or hosts

    return {
        "tool": "nmap",
        "hosts": hosts,
        "open_ports": open_ports,
        "ports_probed": ports_probed,
        "attempts": attempts,
    }


def parse(tool: str, text: str) -> dict[str, Any]:
    """Dispatch to the parser for ``tool``."""
    tool = tool.lower().strip()
    if tool == "hydra":
        return parse_hydra(text)
    if tool == "nmap":
        return parse_nmap(text)
    raise ValueError(f"Unsupported tool {tool!r}; expected one of {SUPPORTED_TOOLS}")


def build_campaign_fact(
    attack_type: str,
    source_ip: str,
    start_time: str,
    end_time: str,
    *,
    tool: str | None = None,
    log_text: str | None = None,
    malicious_attempts: int | None = None,
) -> dict[str, Any]:
    """
    Build one ground-truth campaign entry, deriving ``malicious_attempts`` from a
    tool log when supplied (preferred) or falling back to an explicit count.
    """
    attempts = malicious_attempts
    parsed: dict[str, Any] = {}
    if tool and log_text:
        parsed = parse(tool, log_text)
        attempts = parsed.get("attempts", attempts)

    if attempts is None:
        raise ValueError(
            "Provide either a parseable tool log or an explicit malicious_attempts count."
        )

    fact = {
        "attack_type": attack_type,
        "source_ip": source_ip,
        "start_time": start_time,
        "end_time": end_time,
        "malicious_attempts": int(attempts),
    }
    if parsed:
        fact["ground_truth_source"] = parsed["tool"]
    log.info(
        "Built campaign fact for %s from %s: %d attempts",
        attack_type,
        tool or "manual",
        fact["malicious_attempts"],
    )
    return fact
