"""
config.py
=========
Central configuration for the SOC dashboard.

All sensitive values (URLs, credentials) are read from environment variables so
that nothing secret is ever hard-coded into the source tree. For the live lab,
export the variables before launching Streamlit, e.g.:

    export WAZUH_API_URL="https://10.0.0.10:55000"
    export WAZUH_API_USER="wazuh-wui"
    export WAZUH_API_PASSWORD="••••••••"
    export WAZUH_INDEXER_URL="https://10.0.0.10:9200"
    export WAZUH_INDEXER_USER="admin"
    export WAZUH_INDEXER_PASSWORD="••••••••"

The dashboard ingests real data from three sources (see ingest.py):
  * the live Wazuh north-bound API / Indexer,
  * real Suricata ``eve.json`` log files (NDJSON, optionally gzipped),
  * exported Wazuh alert JSON (array or NDJSON).

A labelled mock dataset (mock_data_generator.py) is available only for offline
development before the lab is producing data.
"""

from __future__ import annotations

import os


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


# Project layout. This file lives in ``<root>/src/config.py``; runtime data and
# curated config JSONs live at the project root (one level up), so resolve both
# relative to the repository root rather than this package directory.
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))  # <root>/src
_ROOT = os.path.dirname(_PKG_DIR)  # <root>


class Settings:
    """Runtime configuration resolved from the process environment."""

    # ------------------------------------------------------------------ #
    # Wazuh Manager — north-bound RESTful API (default port 55000).
    # Used for authentication (JWT) and manager / agent metadata.
    # ------------------------------------------------------------------ #
    WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
    WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh")
    WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "")

    # ------------------------------------------------------------------ #
    # Wazuh Indexer (OpenSearch, default port 9200).
    # This is where the correlated Suricata + host alerts physically live
    # (the `wazuh-alerts-*` index). The dashboard reads alerts from here.
    # ------------------------------------------------------------------ #
    WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
    WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
    WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")
    ALERTS_INDEX = os.getenv("WAZUH_ALERTS_INDEX", "wazuh-alerts-*")
    # Per-request page size for indexer pagination (OpenSearch caps a page at 10k).
    INDEXER_PAGE_SIZE = _env_int("WAZUH_PAGE_SIZE", 10000)

    # ------------------------------------------------------------------ #
    # HTTP behaviour. Lab deployments almost always use self-signed certs,
    # so SSL verification defaults to OFF — set WAZUH_VERIFY_SSL=true once
    # you install a trusted CA bundle.
    # ------------------------------------------------------------------ #
    VERIFY_SSL = _env_bool("WAZUH_VERIFY_SSL", False)
    REQUEST_TIMEOUT = _env_int("WAZUH_REQUEST_TIMEOUT", 30)
    MAX_ALERTS = _env_int("WAZUH_MAX_ALERTS", 5000)

    # Resilience: retry transient HTTP failures with exponential backoff.
    HTTP_RETRIES = _env_int("WAZUH_HTTP_RETRIES", 3)
    HTTP_BACKOFF = float(os.getenv("WAZUH_HTTP_BACKOFF", "0.5"))

    # ------------------------------------------------------------------ #
    # Real Suricata / Wazuh file ingestion paths.
    #   SURICATA_EVE_PATH  — path to a live eve.json (NDJSON, .json or .gz).
    #   WAZUH_EXPORT_PATH  — path to an exported Wazuh alerts file
    #                        (JSON array or NDJSON).
    # ------------------------------------------------------------------ #
    SURICATA_EVE_PATH = os.getenv("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
    WAZUH_EXPORT_PATH = os.getenv("WAZUH_EXPORT_PATH", "")

    # ------------------------------------------------------------------ #
    # Local mock dataset locations (offline development only).
    # ------------------------------------------------------------------ #
    DATA_DIR = os.getenv("SOC_DATA_DIR", os.path.join(_ROOT, "data"))
    ALERTS_FILE = os.path.join(DATA_DIR, "wazuh_alerts.json")
    GROUND_TRUTH_FILE = os.path.join(DATA_DIR, "ground_truth.json")
    EVE_FILE = os.path.join(DATA_DIR, "suricata_eve.json")
    # Repeated experiment runs (run_01/, run_02/, …) for the variance/CI analysis.
    RUNS_DIR = os.path.join(DATA_DIR, "runs")

    # Dissertation artefacts (methodology, lab guide, generated benchmark CSV, …).
    DOCS_DIR = os.path.join(_ROOT, "docs")

    # Where browser-uploaded eve.json / Wazuh exports are saved before ingestion,
    # and bundled sample files the user can try the upload flow with.
    UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
    SAMPLES_DIR = os.path.join(DATA_DIR, "samples")
    SAMPLE_EVE_PATH = os.path.join(SAMPLES_DIR, "sample_eve.json")
    SAMPLE_WAZUH_EXPORT_PATH = os.path.join(SAMPLES_DIR, "sample_wazuh_export.json")

    # Incident triage state (status/notes), persisted across sessions.
    INCIDENT_STATE_FILE = os.path.join(DATA_DIR, "incident_state.json")

    # Local, analyst-curated threat-intel feed (offline by default — see
    # enrichment.py). Override with your own feed via THREAT_INTEL_FILE.
    THREAT_INTEL_FILE = os.getenv(
        "THREAT_INTEL_FILE",
        os.path.join(_ROOT, "config", "threat_intel.json"),
    )
    # Online TI lookups (AbuseIPDB/GreyNoise/…) are OFF by default. They are NOT
    # performed unless explicitly enabled AND a key is supplied; the dashboard
    # never contacts external services on its own.
    TI_ONLINE_ENABLED = _env_bool("THREAT_INTEL_ONLINE", False)

    # Logging level for the whole app.
    LOG_LEVEL = os.getenv("SOC_LOG_LEVEL", "INFO")

    # ------------------------------------------------------------------ #
    # Optional dashboard authentication (OFF by default so the demo and
    # tests are not gated). Enable in production with:
    #   SOC_AUTH_ENABLED=true
    #   SOC_AUTH_USERNAME=analyst
    #   SOC_AUTH_PASSWORD_HASH=<sha256 hex of the password>
    # Generate a hash:  python -c "import hashlib,getpass;print(hashlib.sha256(getpass.getpass().encode()).hexdigest())"
    # A plaintext SOC_AUTH_PASSWORD is supported as a fallback but discouraged.
    # ------------------------------------------------------------------ #
    AUTH_ENABLED = _env_bool("SOC_AUTH_ENABLED", False)
    AUTH_USERNAME = os.getenv("SOC_AUTH_USERNAME", "analyst")
    AUTH_PASSWORD_HASH = os.getenv("SOC_AUTH_PASSWORD_HASH", "")
    # Read the hash from a file instead (Docker/K8s secret pattern).
    AUTH_PASSWORD_HASH_FILE = os.getenv("SOC_AUTH_PASSWORD_HASH_FILE", "")
    AUTH_PASSWORD = os.getenv("SOC_AUTH_PASSWORD", "")

    # Append-only audit log of logins / exports (who did what, when).
    AUDIT_LOG_FILE = os.getenv("SOC_AUDIT_LOG", os.path.join(DATA_DIR, "audit.log"))

    # Asset inventory (host criticality) — drives the composite risk score.
    ASSETS_FILE = os.getenv(
        "SOC_ASSETS_FILE",
        os.path.join(_ROOT, "config", "assets.json"),
    )

    # Persisted UI preferences (data source, filters).
    PREFS_FILE = os.path.join(DATA_DIR, "ui_prefs.json")

    # Optional outbound webhook for critical-incident notifications. OFF unless a
    # URL is set; the dashboard never posts anywhere on its own otherwise.
    WEBHOOK_URL = os.getenv("SOC_WEBHOOK_URL", "")
    WEBHOOK_MIN_LEVEL = _env_int("SOC_WEBHOOK_MIN_LEVEL", 12)  # notify on level >= this

    def has_live_credentials(self) -> bool:
        """True when enough is configured to attempt a live indexer query."""
        return bool(self.WAZUH_INDEXER_PASSWORD and self.WAZUH_INDEXER_USER)


# Singleton imported across the project.
settings = Settings()
