#!/usr/bin/env python3
"""
build_ground_truth.py
=====================
Turn a ``run_manifest.json`` produced by ``lab/run_attacks.sh`` (plus the tool
output files) into a **real** ``data/ground_truth.json`` — measured facts only.

``malicious_attempts`` is derived directly from the nmap / hydra output via
``src/attack_logs.py``; the attacker IP and the UTC time windows come straight
from the manifest. Nothing is fabricated. Counts a tool cannot report (hping3,
curl) are left at 0 with a ``_TODO`` note for you to fill from your own records.

Usage:
    python lab/build_ground_truth.py --manifest run_manifest.json \
        --out data/ground_truth.json --benign-events 0
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Make the project's attack-log parsers importable.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

import attack_logs  # noqa: E402  (path set above)

# Representative ATT&CK techniques per attack class (matches mitre_mapping.py).
_TECH = {
    "Scan": ["T1595", "T1046", "T1018"],
    "Brute Force": ["T1110", "T1110.001"],
    "DoS": ["T1498", "T1499"],
    "Exploit Delivery": ["T1190", "T1203", "T1059"],
}


def build(manifest_path: str, benign_events: int) -> dict:
    """Build the ground-truth dict from a run manifest + its tool logs."""
    base = os.path.dirname(os.path.abspath(manifest_path))
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)

    campaigns = []
    for r in manifest:
        attempts = None
        tool, log_file = r.get("tool"), r.get("log_file")
        if tool in ("nmap", "hydra") and log_file:
            p = log_file if os.path.isabs(log_file) else os.path.join(base, log_file)
            if os.path.exists(p):
                with open(p, encoding="utf-8", errors="replace") as lf:
                    attempts = attack_logs.parse(tool, lf.read()).get("attempts")

        campaign = {
            "attack_type": r["attack_type"],
            "source_ip": r["source_ip"],
            "target_ip": r.get("target_ip"),
            "start_time": r["start_time"],
            "end_time": r["end_time"],
            "malicious_attempts": int(attempts) if attempts is not None else 0,
            "mitre_techniques": _TECH.get(r["attack_type"], []),
        }
        if attempts is None:
            campaign["_TODO"] = "set malicious_attempts manually (tool reported no count)"
        campaigns.append(campaign)

    return {
        "note": "Measured lab facts only — derived from lab/run_attacks.sh output.",
        "campaigns": campaigns,
        "benign": {"benign_events": benign_events},
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build ground_truth.json from a lab run.")
    ap.add_argument("--manifest", required=True, help="run_manifest.json from run_attacks.sh")
    ap.add_argument("--out", default="data/ground_truth.json")
    ap.add_argument(
        "--benign-events",
        type=int,
        default=0,
        help="size of the benign population from your baseline capture",
    )
    args = ap.parse_args(argv)

    gt = build(args.manifest, args.benign_events)
    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(gt, fh, indent=2)

    print(f"Wrote {args.out} with {len(gt['campaigns'])} campaigns.")
    todo = [c["attack_type"] for c in gt["campaigns"] if "_TODO" in c]
    if todo:
        print(f"  Set malicious_attempts manually for: {', '.join(todo)}")
    if args.benign_events == 0:
        print("  REMEMBER: set benign.benign_events from a quiet baseline capture.")
    print("  Then: python src/validate_run.py --source wazuh_api   (or your source)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
