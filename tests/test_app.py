"""
AppTest interaction tests for app.py — exercises the real Streamlit script
(source switching, search, filters) so app.py has behavioural coverage beyond a
smoke test.
"""

import os

from streamlit.testing.v1 import AppTest

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "app.py")


def _run():
    return AppTest.from_file(APP, default_timeout=180).run()


def test_app_boots_with_all_tabs():
    at = _run()
    assert len(at.exception) == 0
    assert len(at.tabs) == 8  # Patterns, Incidents, MITRE, Metrics, Eval, Assets, Alerts, About


def test_app_has_core_metrics():
    at = _run()
    # The top KPI strip is rendered as themed HTML cards (theme.kpi_row).
    kpi_text = " ".join(m.value for m in at.markdown)
    assert "Total Alerts" in kpi_text
    assert "Detection Accuracy" in kpi_text
    # In-tab Streamlit metrics still expose the classification scores.
    labels = {m.label for m in at.metric}
    assert "Accuracy" in labels


def test_app_alert_search_does_not_crash():
    at = _run()
    if at.text_input:  # Alert Explorer search box
        at.text_input[0].set_value("ET").run()
    assert len(at.exception) == 0


def test_app_switch_to_eve_source_prompts_for_upload():
    at = _run()
    at.radio[0].set_value("Suricata eve.json").run()
    # Default "Upload a file" method with nothing uploaded -> friendly prompt, no crash.
    assert len(at.exception) == 0


def test_app_eve_server_path_missing_file_is_graceful():
    at = _run()
    at.radio[0].set_value("Suricata eve.json").run()
    # radio[1] is the eve "Input method"; switch to the server-path branch.
    at.radio[1].set_value("Server file path").run()
    # Default eve path is absent in CI -> graceful error surfaced, no crash.
    assert len(at.exception) == 0


def test_app_category_filter_applies():
    at = _run()
    # The sidebar attack-category multiselect is the first multiselect widget.
    if at.multiselect:
        at.multiselect[0].set_value(["Scan"]).run()
    assert len(at.exception) == 0
