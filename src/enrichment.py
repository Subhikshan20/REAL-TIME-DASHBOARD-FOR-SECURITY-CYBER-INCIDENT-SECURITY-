"""
enrichment.py
=============
Context enrichment for source IPs: network-scope classification + threat-intel
verdict, used in the incident drill-down and alert views.

Privacy / safety: enrichment is **fully offline by default**. It uses Python's
``ipaddress`` for scope classification and a local, analyst-curated indicator
feed (``threat_intel.json``) for the threat-intel verdict. The dashboard never
contacts external services on its own. Online lookups (AbuseIPDB / GreyNoise /
VirusTotal) are intentionally left as an opt-in integration point only — see
``settings.TI_ONLINE_ENABLED`` — and are not implemented here so no user data is
sent anywhere without the operator wiring it up deliberately.
"""

from __future__ import annotations

import ipaddress
import json
import os
from functools import lru_cache
from typing import Any

from config import settings
from logging_config import get_logger

log = get_logger("enrichment")

# Colour-blind-safe (Okabe–Ito) verdict colours.
VERDICT_COLORS = {
    "malicious": "#D55E00",
    "suspicious": "#E69F00",
    "internal": "#0072B2",
    "unknown": "#999999",
}


@lru_cache(maxsize=1)
def _load_indicators_cached(path: str, mtime: float) -> tuple:
    """Cached indicator load keyed on path + mtime (mtime busts the cache)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Could not load threat-intel feed %s: %s", path, exc)
        return tuple()
    inds = data.get("indicators", data) if isinstance(data, dict) else data
    return tuple(inds) if isinstance(inds, list) else tuple()


def load_indicators(path: str | None = None) -> list[dict[str, Any]]:
    """Load the local threat-intel indicator list (empty if absent/invalid)."""
    path = path or settings.THREAT_INTEL_FILE
    if not path or not os.path.exists(path):
        return []
    return list(_load_indicators_cached(path, os.path.getmtime(path)))


# RFC1918 / link-local define a genuinely *internal* host. Note: recent Python
# (3.12+) marks documentation/TEST-NET ranges as `is_private`, which is too broad
# for SOC use (lab attacker IPs often live in those ranges), so we classify
# scope explicitly here.
_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_DOCUMENTATION = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]


def ip_classification(ip: Any) -> dict[str, Any]:
    """Classify an IP's network scope (RFC1918 internal vs public vs doc/reserved)."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except (ValueError, TypeError):
        return {"valid": False, "scope": "unknown", "is_private": False, "version": None}

    internal = addr.is_loopback or addr.is_link_local or any(addr in n for n in _RFC1918)
    if internal:
        scope = "private"
    elif any(addr in n for n in _DOCUMENTATION):
        scope = "documentation"
    elif addr.is_multicast or addr.is_reserved:
        scope = "reserved"
    elif addr.is_global:
        scope = "public"
    else:
        scope = "special"
    return {"valid": True, "scope": scope, "is_private": bool(internal), "version": addr.version}


def match_indicators(ip: Any, indicators: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the first matching indicator (exact IP or CIDR membership)."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except (ValueError, TypeError):
        return None
    for ind in indicators:
        value = str(ind.get("indicator", ""))
        itype = ind.get("type", "ip")
        try:
            if itype == "cidr":
                if addr in ipaddress.ip_network(value, strict=False):
                    return ind
            elif value == str(ip):
                return ind
        except ValueError:
            continue
    return None


def enrich_ip(ip: Any, indicators: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """
    Combine scope classification and the local threat-intel verdict for an IP.

    Returns a dict with: ip, scope, is_private, ti_verdict, ti_tags, ti_source,
    ti_confidence.
    """
    indicators = load_indicators() if indicators is None else indicators
    cls = ip_classification(ip)
    hit = match_indicators(ip, indicators)

    # A known-bad indicator wins regardless of scope; otherwise RFC1918 hosts are
    # "internal" and everything else with no intel is "unknown".
    if hit:
        verdict = str(hit.get("severity", "malicious"))
        source = "local-indicators"
    elif cls.get("is_private"):
        verdict = "internal"
        source = "rfc1918"
    else:
        verdict = "unknown"
        source = "none"

    return {
        "ip": str(ip),
        "scope": cls.get("scope"),
        "is_private": cls.get("is_private"),
        "ti_verdict": verdict,
        "ti_tags": list(hit.get("tags", [])) if hit else [],
        "ti_source": source,
        "ti_confidence": hit.get("confidence") if hit else None,
    }
