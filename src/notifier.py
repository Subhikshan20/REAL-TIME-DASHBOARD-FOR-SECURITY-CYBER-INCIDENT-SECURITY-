"""
notifier.py
===========
Opt-in outbound notifications for critical incidents (generic JSON webhook,
Slack-compatible).

Safety: this is the only component that can send data off-host, so it is
**inert by default**. Nothing is ever posted unless an operator has configured
``SOC_WEBHOOK_URL`` *and* explicitly triggers a send (a button / enabled toggle).
The dashboard never auto-posts on its own initiative.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from config import settings
from logging_config import get_logger

log = get_logger("notifier")

_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
_SEV_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Unknown": "⚪"}


def critical_incidents(inc_df: pd.DataFrame, min_band: str = "Critical") -> pd.DataFrame:
    """Incidents at/above a severity band (default Critical) — the notify set."""
    if inc_df.empty or "severity" not in inc_df:
        return inc_df.iloc[0:0] if not inc_df.empty else inc_df
    threshold = _SEV_RANK.get(min_band, 4)
    mask = inc_df["severity"].map(lambda s: _SEV_RANK.get(s, 0) >= threshold)
    return inc_df[mask]


def build_payload(inc_df: pd.DataFrame, source_label: str = "") -> dict[str, Any]:
    """Build a Slack-compatible JSON payload summarising the incidents."""
    rows = critical_incidents(inc_df)
    lines = [
        f"• *{r['attack_category']}* from `{r['src_ip']}` "
        f"({r['severity']}, {int(r['alert_count'])} alerts → {r.get('layers', '')})"
        for _, r in rows.iterrows()
    ]
    text = (
        f":rotating_light: *SOC Dashboard* — {len(rows)} critical incident(s)"
        + (f" [{source_label}]" if source_label else "")
        + ("\n" + "\n".join(lines) if lines else "")
    )
    return {"text": text, "incident_count": int(len(rows))}


def summary_markdown(inc_df: pd.DataFrame, source_label: str = "") -> str:
    """Human-readable, Streamlit-rendered summary of the critical incidents.

    Unlike :func:`build_payload` (which emits Slack *mrkdwn* for the webhook),
    this returns standard Markdown with real emoji so the dashboard preview
    renders cleanly instead of showing raw ``:shortcode:`` / ``*`` syntax. It is
    fully data-driven — every line reflects the current incident stream.
    """
    rows = critical_incidents(inc_df)
    if rows.empty:
        return "✅ **No critical incidents** in the current view."
    suffix = f" · _{source_label}_" if source_label else ""
    header = f"🚨 **{len(rows)} critical incident(s)**{suffix}"
    items = "\n".join(
        f"- {_SEV_EMOJI.get(r['severity'], '⚪')} **{r['attack_category']}** "
        f"from `{r['src_ip']}` — {int(r['alert_count'])} alerts · {r.get('layers', '') or 'n/a'}"
        for _, r in rows.iterrows()
    )
    return f"{header}\n\n{items}"


def send_webhook(
    payload: dict[str, Any], url: str | None = None, timeout: int = 10
) -> tuple[bool, str]:
    """
    POST ``payload`` as JSON to the configured webhook. Returns (ok, message).

    Never raises; connection problems are returned as a failure message so the UI
    can surface them. Requires an explicit URL (config or argument).
    """
    url = url or settings.WEBHOOK_URL
    if not url:
        return False, "No webhook URL configured (set SOC_WEBHOOK_URL)."
    try:
        import requests

        resp = requests.post(url, json=payload, timeout=timeout)
        ok = 200 <= resp.status_code < 300
        msg = f"HTTP {resp.status_code}"
        log.info("Webhook POST to %s -> %s", url, msg)
        return ok, msg
    except Exception as exc:  # noqa: BLE001 - surface any transport error to the UI
        log.warning("Webhook POST failed: %s", exc)
        return False, str(exc)
