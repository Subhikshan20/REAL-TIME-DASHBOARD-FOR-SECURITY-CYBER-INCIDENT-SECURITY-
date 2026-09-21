"""
theme.py
========
The dashboard's visual design system. A single ``inject(mode, accent)`` call
themes the whole app — Streamlit chrome (CSS) and every Plotly chart (template) —
from one palette, so Dark/Light mode and the accent colour are switchable at
runtime from the sidebar.

Public API:
    inject(mode, accent)          — activate palette + inject CSS + Plotly template.
    header(title, subtitle, chips)— branded header bar with live status chips.
    kpi_row(items)                — responsive KPI cards that never truncate.
    MODES / ACCENTS               — the available choices (for the sidebar).
"""

from __future__ import annotations

import html as _html
import re as _re

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st

# Colour-blind-safe (Okabe–Ito) categorical sequence for chart DATA series
# (kept constant across themes so series stay distinguishable and comparable).
OKABE_ITO = [
    "#0072B2",
    "#E69F00",
    "#009E73",
    "#D55E00",
    "#CC79A7",
    "#56B4E9",
    "#F0E442",
    "#999999",
]

_FONT = '"Inter", "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif'

MODES = ["System", "Dark", "Light"]

# Steady brand accent (same in both themes) — calm, not alarming.
_BASE_ACCENT = ("#3b82f6", "#22d3ee")

# Live threat posture is shown as a SUBTLE coloured chip (not by recolouring the
# whole UI). Each posture maps to a chip tone colour.
POSTURE_TONE = {
    "All clear": "#10b981",
    "Nominal": "#3b82f6",
    "Elevated": "#e6900b",
    "Critical": "#e5484d",
}

# Per-mode palette. `plot_*` keys feed the Plotly template.
_PALETTES = {
    "Dark": {
        "bg": "#0a0e16",
        "bg2": "#0a0d14",
        "surface": "#141a26",
        "surface2": "#1b2230",
        "border": "rgba(255,255,255,.08)",
        "text": "#e7ebf3",
        "muted": "#9aa4b2",
        "card_strong": "#ffffff",
        "grid": "rgba(255,255,255,.022)",
        "scroll": "rgba(255,255,255,.14)",
        "plot_font": "#c7cedb",
        "plot_grid": "rgba(255,255,255,0.06)",
        "plot_axis": "#9aa4b2",
        "plot_title": "#eef2f8",
    },
    "Light": {
        "bg": "#eef2f8",
        "bg2": "#e6ecf5",
        "surface": "#ffffff",
        "surface2": "#f3f6fb",
        "border": "rgba(15,30,55,.12)",
        "text": "#16202e",
        "muted": "#5b6675",
        "card_strong": "#0f1b2d",
        "grid": "rgba(20,40,80,.05)",
        "scroll": "rgba(20,40,80,.18)",
        "plot_font": "#33414f",
        "plot_grid": "rgba(20,40,80,0.08)",
        "plot_axis": "#5b6675",
        "plot_title": "#16202e",
    },
}


def _register_plotly_template(p: dict) -> None:
    """Register + activate a Plotly template matching the active palette."""
    pio.templates["soc"] = go.layout.Template(
        layout=dict(
            colorway=OKABE_ITO,
            font=dict(family=_FONT, size=13, color=p["plot_font"]),
            # Explicit surface bg (matches the chart card) so every chart follows the
            # runtime Light/Dark mode regardless of Streamlit's own theme config.
            paper_bgcolor=p["surface"],
            plot_bgcolor=p["surface"],
            title=dict(font=dict(size=15, color=p["plot_title"]), x=0.01, xanchor="left"),
            xaxis=dict(
                gridcolor=p["plot_grid"],
                zerolinecolor=p["plot_grid"],
                linecolor=p["plot_grid"],
                tickfont=dict(color=p["plot_axis"]),
            ),
            yaxis=dict(
                gridcolor=p["plot_grid"],
                zerolinecolor=p["plot_grid"],
                linecolor=p["plot_grid"],
                tickfont=dict(color=p["plot_axis"]),
            ),
            legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color=p["plot_font"])),
            margin=dict(t=52, l=14, r=14, b=14),
            colorscale=dict(sequential=[[0.0, "#0b2740"], [0.5, "#1f6aa5"], [1.0, "#56B4E9"]]),
            hoverlabel=dict(font=dict(family=_FONT, size=12)),
        )
    )
    base = "plotly_dark" if p is _PALETTES["Dark"] else "plotly_white"
    pio.templates.default = f"{base}+soc"
    px.defaults.template = f"{base}+soc"
    px.defaults.color_discrete_sequence = OKABE_ITO
    px.defaults.height = 380  # bigger charts by default (overridable per-figure)


def _vars_decl(p: dict, a1: str, a2: str) -> str:
    """The CSS custom-property declarations for a palette (no :root wrapper)."""
    return (
        f"--bg:{p['bg']};--bg2:{p['bg2']};--surface:{p['surface']};--surface2:{p['surface2']};"
        f"--border:{p['border']};--text:{p['text']};--muted:{p['muted']};"
        f"--accent:{a1};--accent2:{a2};--card-strong:{p['card_strong']};"
        f"--grid:{p['grid']};--scroll:{p['scroll']};"
    )


# In "System" mode the chrome palette adapts to the OS via these media queries, and
# the chart text (which Plotly draws server-side and can't know the OS theme) is
# nudged to a readable colour for each scheme.
_TEXT_SELECTORS = (
    ".js-plotly-plot .xtick>text,.js-plotly-plot .ytick>text,.js-plotly-plot text.gtitle,"
    ".js-plotly-plot text.xtitle,.js-plotly-plot text.ytitle,.js-plotly-plot .legendtext,"
    ".js-plotly-plot .legendtitletext,.js-plotly-plot .sankey .node-label,"
    ".js-plotly-plot .sankey text"
)
_PLOTLY_TEXT_MEDIA = (
    f"@media (prefers-color-scheme:light){{{_TEXT_SELECTORS}{{fill:#16202e !important;}}}}"
    f"@media (prefers-color-scheme:dark){{{_TEXT_SELECTORS}{{fill:#f1f4f9 !important;}}}}"
)


# CSS body references the variables above; it is theme-agnostic.
_CSS_BODY = """
/* ---- App canvas: faint grid + accent glow + base gradient --------------- */
/* The grid is part of the .stApp background (fixed attachment) — NOT a ::before
   overlay, which previously needed a z-index on the view container and broke the
   sidebar's height/scroll. */
.stApp{
  background:
    linear-gradient(var(--grid) 1px, transparent 1px),
    linear-gradient(90deg, var(--grid) 1px, transparent 1px),
    radial-gradient(1200px 620px at 8% -10%, color-mix(in srgb, var(--accent) 14%, transparent), transparent 60%),
    radial-gradient(1000px 520px at 100% 0%, color-mix(in srgb, var(--accent2) 10%, transparent), transparent 55%),
    linear-gradient(180deg, var(--bg), var(--bg2)) !important;
  background-size:34px 34px, 34px 34px, 100% 100%, 100% 100%, 100% 100% !important;
  background-attachment:fixed !important;
}
.block-container{padding-top:1.8rem; padding-bottom:3rem; max-width:1580px; animation:soc-fade .35s ease both;}
@keyframes soc-fade{from{opacity:0; transform:translateY(6px);} to{opacity:1; transform:none;}}
html, body, [class*="css"]{font-family:"Inter","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;}
.stApp, .block-container, [data-testid="stMarkdownContainer"]{color:var(--text);}

/* Make sure the sidebar is viewport-bounded and scrolls internally. */
[data-testid="stSidebar"]{height:100vh !important;}
[data-testid="stSidebarContent"]{height:100vh !important; overflow-y:auto !important;}

/* keep Streamlit chrome clean but the sidebar control reachable (Safari fix) */
[data-testid="stDecoration"]{display:none;}
[data-testid="stAppDeployButton"]{display:none;}
[data-testid="stHeader"]{background:transparent;}
[data-testid="stSidebarCollapseButton"], [data-testid="stSidebarCollapseButton"] button,
[data-testid="stExpandSidebarButton"], [data-testid="stSidebarCollapsedControl"],
[data-testid="collapsedControl"]{visibility:visible !important; opacity:1 !important; z-index:1000 !important;}

/* headings + section accent bar */
h1,h2,h3{letter-spacing:-.01em; color:var(--text);}
.block-container h2, .block-container h3{position:relative; padding-left:14px; margin-top:.25rem;}
.block-container h2::before, .block-container h3::before{content:""; position:absolute; left:0;
  top:.14em; bottom:.14em; width:4px; border-radius:3px;
  background:linear-gradient(180deg,var(--accent),var(--accent2));
  box-shadow:0 0 10px color-mix(in srgb, var(--accent) 55%, transparent);}
.block-container h4, .block-container h5{color:var(--muted) !important; text-transform:uppercase;
  letter-spacing:.07em; font-size:12px !important; font-weight:700 !important; margin-bottom:.2rem;}

/* ---- Branded header (always a dark accent banner; works in both modes) -- */
.soc-header{position:relative; overflow:hidden; display:flex; justify-content:space-between;
  align-items:center; gap:18px; flex-wrap:wrap; padding:18px 22px; margin:0 0 18px 0; border-radius:18px;
  background:linear-gradient(135deg, color-mix(in srgb, var(--accent) 42%, transparent),
    color-mix(in srgb, var(--accent2) 14%, transparent)), linear-gradient(135deg,#10243f,#0b1626);
  border:1px solid rgba(255,255,255,.10); box-shadow:0 12px 36px rgba(0,0,0,.30);}
.soc-header::after{content:""; position:absolute; inset:0; pointer-events:none;
  background:linear-gradient(115deg, transparent 40%, rgba(255,255,255,.06) 50%, transparent 60%);
  background-size:250% 100%; animation:soc-sheen 7s linear infinite;}
@keyframes soc-sheen{from{background-position:120% 0;} to{background-position:-120% 0;}}
.soc-header-main{display:flex; align-items:center; gap:15px; min-width:0;}
.soc-logo{width:48px; height:48px; border-radius:13px; display:grid; place-items:center; font-size:25px;
  background:linear-gradient(135deg,var(--accent),var(--accent2)); box-shadow:0 6px 20px rgba(0,0,0,.4); flex:none;}
.soc-title{font-size:23px; font-weight:800; color:#fff; line-height:1.12;}
.soc-sub{font-size:12.5px; color:#c4d2e4; margin-top:3px;}
.soc-chips{display:flex; gap:10px; flex-wrap:wrap; justify-content:flex-end;}
.soc-chip{background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.16); color:#cfdaea;
  padding:7px 12px; border-radius:10px; font-size:12px; white-space:nowrap;}
.soc-chip b{color:#fff; font-weight:700;}
.soc-dot{display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; background:#22c55e;
  box-shadow:0 0 0 3px rgba(34,197,94,.18); animation:soc-pulse 2s ease-in-out infinite;}
@keyframes soc-pulse{0%,100%{box-shadow:0 0 0 3px rgba(34,197,94,.18);} 50%{box-shadow:0 0 0 6px rgba(34,197,94,.05);}}

/* ---- KPI cards ---------------------------------------------------------- */
.kpi-row{display:grid; grid-template-columns:repeat(auto-fit,minmax(172px,1fr)); gap:15px; margin:2px 0 6px;}
.kpi-card{position:relative; overflow:hidden; background:linear-gradient(180deg, var(--surface), var(--surface2));
  border:1px solid var(--border); border-radius:16px; padding:16px 18px; box-shadow:0 6px 20px rgba(0,0,0,.18);
  transition:transform .14s ease, border-color .14s ease;}
.kpi-card:hover{transform:translateY(-3px); border-color:color-mix(in srgb, var(--accent) 55%, transparent);}
.kpi-card::before{content:""; position:absolute; left:0; top:0; bottom:0; width:4px; background:var(--kpi-accent,var(--accent));}
.kpi-top{display:flex; align-items:center; gap:8px; color:var(--muted); font-size:11px; font-weight:700;
  text-transform:uppercase; letter-spacing:.05em;}
.kpi-ic{font-size:14px; line-height:1;}
.kpi-val{font-size:clamp(1.5rem, 2.1vw, 2.15rem); font-weight:800; color:var(--card-strong); line-height:1.1; margin-top:7px;}
.kpi-sub{margin-top:6px; font-size:12px; font-weight:700;}
.kpi-sub.good{color:#16a34a;} .kpi-sub.bad{color:#dc2626;} .kpi-sub.muted{color:var(--muted);}

/* in-tab st.metric cards */
[data-testid="stMetric"]{background:linear-gradient(180deg, var(--surface), var(--surface2));
  border:1px solid var(--border); border-left:3px solid var(--accent); border-radius:14px; padding:14px 16px;
  box-shadow:0 4px 16px rgba(0,0,0,.14); transition:transform .12s ease, border-color .12s ease;}
[data-testid="stMetric"]:hover{transform:translateY(-2px); border-left-color:var(--accent2);}
[data-testid="stMetricLabel"]{color:var(--muted) !important;}
[data-testid="stMetricLabel"] p{font-size:12px !important; font-weight:600; text-transform:uppercase; letter-spacing:.04em;}
[data-testid="stMetricValue"]{font-weight:800 !important; color:var(--card-strong) !important;
  font-size:clamp(1.2rem, 1.7vw, 1.8rem) !important;}

/* ---- Tabs -> wrapping pills, solid accent when selected ----------------- */
.stTabs [data-baseweb="tab-list"]{flex-wrap:wrap; gap:6px; row-gap:6px; border-bottom:1px solid var(--border); padding-bottom:8px;}
.stTabs [data-baseweb="tab"]{background:var(--surface); border:1px solid var(--border); border-radius:10px;
  padding:7px 13px; color:var(--muted); font-weight:600; font-size:13.5px;}
.stTabs [data-baseweb="tab"]:hover{color:var(--text); border-color:color-mix(in srgb, var(--accent) 40%, transparent);}
.stTabs [aria-selected="true"]{background:linear-gradient(135deg, var(--accent), var(--accent2)) !important;
  color:#fff !important; border-color:transparent !important; box-shadow:0 4px 14px color-mix(in srgb, var(--accent) 40%, transparent);}
.stTabs [data-baseweb="tab-highlight"], .stTabs [data-baseweb="tab-border"]{display:none;}

/* ---- Sidebar ------------------------------------------------------------ */
[data-testid="stSidebar"]{background:linear-gradient(180deg, var(--surface), var(--bg)) !important; border-right:1px solid var(--border);}
[data-testid="stSidebar"] .stButton button{width:100%;}

/* ---- Buttons (explicit bg+colour so they read in BOTH themes) ----------- */
.stButton button, .stDownloadButton button{background:var(--surface2) !important; color:var(--text) !important;
  border-radius:10px !important; border:1px solid var(--border) !important; font-weight:600;
  transition:border-color .12s ease, transform .08s ease, background .12s ease;}
.stButton button:hover, .stDownloadButton button:hover{
  border-color:var(--accent) !important; background:color-mix(in srgb, var(--accent) 14%, var(--surface2)) !important;
  transform:translateY(-1px);}
.stButton button p, .stDownloadButton button p, .stButton button span{color:var(--text) !important;}
.stFormSubmitButton button{background:linear-gradient(135deg,var(--accent),var(--accent2)) !important;
  color:#fff !important; border:none !important; border-radius:10px !important; font-weight:700;}
.stFormSubmitButton button p, .stFormSubmitButton button span{color:#fff !important;}

/* sidebar show/hide arrow — high-contrast chip + bold chevron in both themes.
   The chevron is a Material-ICON <span> (not an svg), coloured by Streamlit's
   config text colour — so we override the span/icon `color`, not svg fill. */
[data-testid="stSidebarCollapseButton"] button, [data-testid="stExpandSidebarButton"],
[data-testid="stSidebarCollapsedControl"] button{
  background:var(--surface2) !important; border:1px solid var(--border) !important;
  border-radius:9px !important; box-shadow:0 2px 8px rgba(0,0,0,.18) !important;}
[data-testid="stSidebarCollapseButton"] button *, [data-testid="stExpandSidebarButton"] *,
[data-testid="stSidebarCollapsedControl"] button *,
[data-testid="stSidebarCollapseButton"] [data-testid="stIconMaterial"],
[data-testid="stExpandSidebarButton"] [data-testid="stIconMaterial"]{
  color:var(--text) !important; fill:var(--text) !important; opacity:1 !important;}

/* ---- Form controls ------------------------------------------------------ */
[data-baseweb="select"] > div, [data-baseweb="input"] > div, .stTextInput input, .stNumberInput input,
.stDateInput input, .stTimeInput input{background:var(--surface2) !important; border:1px solid var(--border) !important;
  border-radius:10px !important; color:var(--text) !important;}
[data-baseweb="select"] > div:focus-within, [data-baseweb="input"] > div:focus-within{
  border-color:var(--accent) !important; box-shadow:0 0 0 2px color-mix(in srgb, var(--accent) 22%, transparent) !important;}
[data-baseweb="tag"]{background:linear-gradient(135deg, var(--accent), var(--accent2)) !important;
  border-radius:8px !important; color:#fff !important; font-weight:700 !important;}
/* Placeholders are too faint in baseweb's defaults — force a legible colour in
   both themes for the search box and the "Choose options" multiselects. */
.stTextInput input::placeholder, .stNumberInput input::placeholder,
.stTextArea textarea::placeholder, [data-baseweb="input"] input::placeholder{
  color:var(--muted) !important; opacity:1 !important;}
[data-baseweb="select"] div, [data-baseweb="select"] span{color:var(--text) !important;}
[data-baseweb="select"] [data-baseweb="tag"],
[data-baseweb="select"] [data-baseweb="tag"] *{color:#fff !important;}
[data-testid="stSlider"] [role="slider"]{background:var(--accent) !important;
  box-shadow:0 0 0 4px color-mix(in srgb, var(--accent) 22%, transparent) !important;}

/* ---- Surfaces: tables, expanders, plotly, uploader --------------------- */
[data-testid="stDataFrame"]{border:1px solid var(--border); border-top:2px solid var(--accent);
  border-radius:12px; overflow:hidden; background:var(--surface); box-shadow:0 6px 18px rgba(0,0,0,.16);}
[data-testid="stExpander"]{border:1px solid var(--border); border-radius:12px; overflow:hidden; background:var(--surface);}
[data-testid="stExpander"] summary{font-weight:600; background:linear-gradient(90deg, color-mix(in srgb, var(--accent) 10%, transparent), transparent); border-bottom:1px solid var(--border);}
[data-testid="stPlotlyChart"]{border:1px solid var(--border); border-radius:14px; padding:6px 8px; background:var(--surface);}
/* Streamlit's config theme paints the Plotly SVGs with its (dark) bg; force them
   transparent so the themed card shows through and charts follow the runtime mode. */
.main-svg, .js-plotly-plot .main-svg, [data-testid="stPlotlyChart"] svg{background:transparent !important;}
/* Streamlit's config theme sets the Plotly background RECT fill via CSS (which
   overrides the figure attribute); override it to the surface colour so the plot
   area follows the runtime Light/Dark mode. */
.js-plotly-plot .bg{fill:var(--surface) !important;}
.js-plotly-plot .modebar, .js-plotly-plot .modebar-group{background:transparent !important;}
[data-testid="stFileUploaderDropzone"]{background:var(--surface2); border:1px dashed color-mix(in srgb, var(--accent) 45%, transparent); border-radius:12px;}
[data-testid="stPlotlyChart"], [data-testid="stDataFrame"], [data-testid="stExpander"]{margin-bottom:.55rem;}

/* dividers + scrollbars */
hr{border:none !important; height:1px; background:linear-gradient(90deg, transparent, var(--border), transparent) !important;}
[data-testid="stAlert"]{border-radius:12px;}
*::-webkit-scrollbar{width:10px; height:10px;}
*::-webkit-scrollbar-thumb{background:var(--scroll); border-radius:8px;}
*::-webkit-scrollbar-thumb:hover{background:color-mix(in srgb, var(--accent) 45%, transparent);}
*::-webkit-scrollbar-track{background:transparent;}

.soc-pill{display:inline-block; padding:2px 9px; border-radius:999px; font-size:11.5px; font-weight:700;}

/* ---- Captions / muted text: ensure readable in both themes -------------- */
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p, .stCaption,
[data-testid="stSidebar"] [data-testid="stCaptionContainer"], small{color:var(--muted) !important;}

/* ---- Tooltips (help=): dark bubble needs LIGHT text in BOTH themes -------- */
/* The global markdown colour above otherwise made tooltip text dark-on-dark. */
[data-baseweb="tooltip"], [role="tooltip"], [data-testid="stTooltipContent"]{
  background:#11161f !important; border:1px solid rgba(255,255,255,.14) !important;
  border-radius:10px !important; box-shadow:0 8px 24px rgba(0,0,0,.35) !important;}
[data-baseweb="tooltip"] *, [role="tooltip"] *, [data-testid="stTooltipContent"],
[data-testid="stTooltipContent"] *{color:#f1f4f9 !important;}

/* ---- Toasts (st.toast): readable in BOTH themes ------------------------- */
/* Streamlit's toast otherwise inherits dark text on its dark bubble. Force a
   high-contrast dark bubble with light text + icon in both Light and Dark. */
[data-testid="stToast"], [data-baseweb="toast"]{
  background:#11161f !important; border:1px solid rgba(255,255,255,.18) !important;
  border-radius:12px !important; box-shadow:0 10px 30px rgba(0,0,0,.45) !important;}
[data-testid="stToast"] *, [data-baseweb="toast"] *{color:#f4f7fb !important; fill:#f4f7fb !important;}

/* ---- Posture / tone chips in the header --------------------------------- */
.soc-chip-tone{background:color-mix(in srgb, var(--tone) 18%, transparent) !important;
  border-color:color-mix(in srgb, var(--tone) 55%, transparent) !important; color:#fff !important;}
.soc-chip-tone b{color:#fff !important;}
.soc-tone-dot{display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px;
  background:var(--tone); box-shadow:0 0 0 3px color-mix(in srgb, var(--tone) 28%, transparent);}

/* ---- Themed HTML tables (theme.table) — fully follow Light/Dark ---------- */
.soc-table-wrap{overflow:auto; border:1px solid var(--border); border-top:2px solid var(--accent);
  border-radius:12px; background:var(--surface); box-shadow:0 6px 18px rgba(0,0,0,.16); margin-bottom:.55rem;}
.soc-table{width:100%; border-collapse:collapse; font-size:13px; color:var(--text);}
.soc-table thead th{position:sticky; top:0; z-index:1; background:var(--surface2); color:var(--text);
  text-align:left; padding:9px 12px; font-weight:700; border-bottom:1px solid var(--border); white-space:nowrap;}
.soc-table tbody td{padding:8px 12px; border-bottom:1px solid var(--border); white-space:nowrap; color:var(--text);}
.soc-table tbody tr:last-child td{border-bottom:none;}
.soc-table tbody tr:nth-child(even){background:color-mix(in srgb, var(--surface2) 45%, transparent);}
.soc-table tbody tr:hover{background:color-mix(in srgb, var(--accent) 12%, transparent);}
.soc-bar-wrap{display:inline-block; width:84px; height:8px; background:var(--surface2);
  border:1px solid var(--border); border-radius:6px; margin-right:8px; vertical-align:middle; overflow:hidden;}
.soc-bar{display:block; height:100%; background:linear-gradient(90deg,var(--accent),var(--accent2));}
.soc-bar-val{font-variant-numeric:tabular-nums; color:var(--text);}
.soc-link{color:var(--accent); font-weight:600; text-decoration:none;}
.soc-link:hover{text-decoration:underline;}
"""


def inject(mode: str = "System") -> None:
    """
    Activate the design system: Plotly template + injected CSS.

    ``mode`` is "System" (follow the OS via prefers-color-scheme), "Dark" or
    "Light". The accent is a steady brand colour; threat is shown via the header
    posture chip, not by recolouring the whole UI.
    """
    a1, a2 = _BASE_ACCENT
    if mode == "System":
        # Chrome adapts to the OS; charts handled by template + _PLOTLY_TEXT_MEDIA.
        _register_plotly_template(_PALETTES["Light"])
        css = (
            f":root{{{_vars_decl(_PALETTES['Light'], a1, a2)}}}"
            f"@media (prefers-color-scheme:dark){{:root{{{_vars_decl(_PALETTES['Dark'], a1, a2)}}}}}"
            f"{_CSS_BODY}{_PLOTLY_TEXT_MEDIA}"
        )
    else:
        p = _PALETTES.get(mode, _PALETTES["Dark"])
        _register_plotly_template(p)
        css = f":root{{{_vars_decl(p, a1, a2)}}}{_CSS_BODY}"
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


# Colour values are interpolated into inline ``style="..."`` attributes, so they
# must be constrained to a safe grammar — a hex code, an rgb()/rgba() function or a
# bare CSS keyword. Anything else (a stray ``;``, ``<``, ``url(...)``, ``expression(...)``)
# could break out of the attribute / inject CSS, so it collapses to ``currentColor``.
_COLOR_RE = _re.compile(r"^(#[0-9A-Fa-f]{3,8}|rgba?\([0-9.,%\s]+\)|[A-Za-z]{3,20})$")


def _safe_color(value: object, fallback: str = "currentColor") -> str:
    """Return ``value`` only if it is a safe CSS colour, else ``fallback``."""
    s = str(value or "").strip()
    return s if _COLOR_RE.match(s) else fallback


def header(title: str, subtitle: str, chips: list[tuple]) -> None:
    """
    Render the branded header bar with live status chips.

    Each chip is ``(label, value)`` or ``(label, value, tone_color)`` — when a
    tone colour is given the chip is tinted (used for the threat-posture chip).

    All text is HTML-escaped and colours validated before being interpolated into
    the ``unsafe_allow_html`` markup, so alert-derived strings can never inject.
    """
    parts = []
    for chip in chips:
        label = _html.escape(str(chip[0]))
        value = _html.escape(str(chip[1]))
        tone = _safe_color(chip[2]) if len(chip) > 2 and chip[2] else None
        if tone:
            parts.append(
                f'<span class="soc-chip soc-chip-tone" style="--tone:{tone}">'
                f'<span class="soc-tone-dot"></span>{label}: <b>{value}</b></span>'
            )
        else:
            parts.append(f'<span class="soc-chip">{label}: <b>{value}</b></span>')
    chips_html = "".join(parts)
    st.markdown(
        f"""
        <div class="soc-header">
          <div class="soc-header-main">
            <div class="soc-logo">🛡️</div>
            <div>
              <div class="soc-title">{_html.escape(title)}</div>
              <div class="soc-sub">{_html.escape(subtitle)}</div>
            </div>
          </div>
          <div class="soc-chips"><span class="soc-chip"><span class="soc-dot"></span>live</span>{chips_html}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def table(
    df: pd.DataFrame,
    *,
    bars: dict | None = None,
    links: dict | None = None,
    max_rows: int | None = None,
    height: int | None = None,
) -> None:
    """
    Render a DataFrame as a fully theme-synced HTML table.

    Streamlit's ``st.dataframe`` is a canvas grid that follows the static config
    theme and so cannot switch with the runtime Dark/Light mode — this HTML table
    uses the CSS variables, so it always matches.

    ``bars`` maps a column name to its max value to render an inline progress bar.
    ``links`` maps a column name to the link text (the cell value is the href).
    """
    bars = bars or {}
    links = links or {}
    cols = list(df.columns)

    def _fmt(v: object) -> str:
        if v is None or (isinstance(v, float) and pd.isna(v)):
            return "—"
        if isinstance(v, float):
            return f"{v:,.2f}".rstrip("0").rstrip(".") if v % 1 else f"{int(v):,}"
        if isinstance(v, int):
            return f"{v:,}"
        return str(v)

    head = "".join(f"<th>{_html.escape(str(c))}</th>" for c in cols)
    body = []
    for n, (_, row) in enumerate(df.iterrows()):
        if max_rows is not None and n >= max_rows:
            break
        tds = []
        for c in cols:
            v = row[c]
            if c in links and v:
                cell = (
                    f'<a class="soc-link" href="{_html.escape(str(v))}" target="_blank" '
                    f'rel="noopener">{_html.escape(str(links[c]))}</a>'
                )
            elif c in bars and v is not None and not (isinstance(v, float) and pd.isna(v)):
                try:
                    pct = max(0.0, min(100.0, float(v) / float(bars[c]) * 100.0))
                except (TypeError, ValueError, ZeroDivisionError):
                    pct = 0.0
                cell = (
                    f'<span class="soc-bar-wrap"><span class="soc-bar" style="width:{pct:.0f}%">'
                    f"</span></span><span class='soc-bar-val'>{_html.escape(_fmt(v))}</span>"
                )
            else:
                cell = _html.escape(_fmt(v))
            tds.append(f"<td>{cell}</td>")
        body.append("<tr>" + "".join(tds) + "</tr>")

    style = f' style="max-height:{height}px"' if height else ""
    st.markdown(
        f'<div class="soc-table-wrap"{style}><table class="soc-table">'
        f"<thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table></div>",
        unsafe_allow_html=True,
    )


def kpi_row(items: list[dict]) -> None:
    """
    Render a responsive row of KPI cards.

    Each item: ``label`` + ``value`` plus optional ``icon``, ``accent`` (hex),
    ``sub`` (caption) and ``sub_good`` / ``sub_bad`` flags. The grid wraps and the
    value font scales, so values never truncate the way ``st.metric`` does.
    """
    cards = []
    for it in items:
        sub_html = ""
        if it.get("sub"):
            cls = "good" if it.get("sub_good") else "bad" if it.get("sub_bad") else "muted"
            sub_html = f'<div class="kpi-sub {cls}">{_html.escape(str(it["sub"]))}</div>'
        icon = _html.escape(str(it.get("icon", "")))
        ic_html = f'<span class="kpi-ic">{icon}</span>' if icon else ""
        accent = it.get("accent")
        style = f' style="--kpi-accent:{_safe_color(accent)}"' if accent else ""
        cards.append(
            f'<div class="kpi-card"{style}>'
            f'<div class="kpi-top">{ic_html}{_html.escape(str(it["label"]))}</div>'
            f'<div class="kpi-val">{_html.escape(str(it["value"]))}</div>{sub_html}</div>'
        )
    st.markdown(f'<div class="kpi-row">{"".join(cards)}</div>', unsafe_allow_html=True)
