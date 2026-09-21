"""
test_security.py
================
Output-encoding regression tests for the HTML sinks that use
``unsafe_allow_html``. Alert fields (signatures, source IPs, countries) and an
operator-supplied threat-intel feed are attacker-influenced, so any text or
colour interpolated into raw HTML must be escaped/validated. These tests pin that
behaviour so a future edit cannot reintroduce a cross-site-scripting (XSS) or
CSS-injection sink.
"""

from __future__ import annotations

import theme


def _capture_markdown(monkeypatch) -> dict[str, str]:
    """Replace ``theme.st.markdown`` with a capture so we can inspect the HTML."""
    captured: dict[str, str] = {}
    monkeypatch.setattr(theme.st, "markdown", lambda body, **kw: captured.__setitem__("html", body))
    return captured


def test_safe_color_allows_legitimate_colours():
    assert theme._safe_color("#3b82f6") == "#3b82f6"
    assert theme._safe_color("#D55E00") == "#D55E00"
    assert theme._safe_color("rgba(255,255,255,.20)") == "rgba(255,255,255,.20)"
    assert theme._safe_color("red") == "red"


def test_safe_color_blocks_injection():
    for bad in (
        '"><script>alert(1)</script>',
        "url(javascript:alert(1))",
        "expression(alert(1))",
        "#fff;}body{display:none}",
        "javascript:alert(1)",
        "",
        None,
    ):
        assert theme._safe_color(bad) == "currentColor"


def test_header_escapes_chip_text_and_colour(monkeypatch):
    captured = _capture_markdown(monkeypatch)
    theme.header(
        "Title",
        "Subtitle",
        [
            ("Source", "<img src=x onerror=alert(1)>"),
            ("Posture", "high", '"><script>alert(1)</script>'),
        ],
    )
    out = captured["html"]
    # Raw tag characters must be escaped, not rendered.
    assert "<img" not in out
    assert "<script>" not in out
    assert "&lt;img" in out
    # The malicious tone colour must have collapsed to the safe fallback.
    assert "--tone:currentColor" in out


def test_kpi_row_escapes_values_and_accent(monkeypatch):
    captured = _capture_markdown(monkeypatch)
    theme.kpi_row(
        [
            {
                "label": "<b>label</b>",
                "value": "<script>alert(1)</script>",
                "sub": "<i>sub</i>",
                "icon": "📈",
                "accent": "javascript:alert(1)",
            }
        ]
    )
    out = captured["html"]
    assert "<script>" not in out
    assert "<b>label</b>" not in out
    assert "&lt;script&gt;" in out
    # An invalid accent colour must not reach the style attribute.
    assert "javascript:alert(1)" not in out
    assert "--kpi-accent:currentColor" in out
