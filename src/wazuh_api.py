"""
wazuh_api.py
============
Secure, resilient client for the Wazuh north-bound API and the Wazuh Indexer.

Two surfaces are involved in a Suricata -> Wazuh deployment:

  1. Wazuh Manager RESTful API (port 55000)
     - JWT authentication endpoint (`/security/user/authenticate`)
     - Manager / agent metadata
  2. Wazuh Indexer / OpenSearch (port 9200)
     - The `wazuh-alerts-*` index where the *correlated* Suricata network
       signatures and host-log events are actually stored and searchable.

Production hardening:
  * HTTPS throughout; SSL verification configurable for self-signed lab certs.
  * Automatic retry with exponential backoff on transient HTTP failures
    (429/5xx, connection resets).
  * Transparent JWT refresh + single retry on a 401 (expired token).
  * Structured logging and explicit, typed exceptions.

`fetch_alerts()` returns alert documents in the canonical schema used across the
whole pipeline, so live data flows through exactly the same code paths as the
file-based and mock sources.
"""

from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth

try:  # Silence the noisy warning when verifying self-signed lab certs is off.
    import urllib3
    from urllib3.util.retry import Retry

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover - urllib3 always present with requests
    Retry = None  # type: ignore

from config import settings
from logging_config import get_logger

log = get_logger("wazuh_api")


class WazuhAPIError(RuntimeError):
    """Raised when the Wazuh API / Indexer cannot be reached or returns an error."""


def _build_session(retries: int, backoff: float, verify: bool) -> requests.Session:
    """Create a requests Session with connection pooling + retry policy."""
    session = requests.Session()
    session.verify = verify
    if Retry is not None:
        retry = Retry(
            total=retries,
            connect=retries,
            read=retries,
            backoff_factor=backoff,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
    return session


class WazuhClient:
    """Thin, dependency-light wrapper around the Wazuh north-bound surfaces."""

    def __init__(
        self,
        api_url: str | None = None,
        api_user: str | None = None,
        api_password: str | None = None,
        indexer_url: str | None = None,
        indexer_user: str | None = None,
        indexer_password: str | None = None,
        verify_ssl: bool | None = None,
        timeout: int | None = None,
    ) -> None:
        self.api_url = (api_url or settings.WAZUH_API_URL).rstrip("/")
        self.api_user = api_user or settings.WAZUH_API_USER
        self.api_password = api_password or settings.WAZUH_API_PASSWORD

        self.indexer_url = (indexer_url or settings.WAZUH_INDEXER_URL).rstrip("/")
        self.indexer_user = indexer_user or settings.WAZUH_INDEXER_USER
        self.indexer_password = indexer_password or settings.WAZUH_INDEXER_PASSWORD

        self.verify_ssl = settings.VERIFY_SSL if verify_ssl is None else verify_ssl
        self.timeout = timeout or settings.REQUEST_TIMEOUT

        self._token: str | None = None
        self._session = _build_session(
            settings.HTTP_RETRIES, settings.HTTP_BACKOFF, self.verify_ssl
        )

    # ------------------------------------------------------------------ #
    # Authentication against the Manager API (JWT bearer token).
    # ------------------------------------------------------------------ #
    def authenticate(self) -> str:
        """Obtain a JWT from the Wazuh Manager API and cache it on the client."""
        url = f"{self.api_url}/security/user/authenticate"
        log.info("Authenticating to Wazuh Manager API at %s", self.api_url)
        try:
            resp = self._session.post(
                url,
                auth=HTTPBasicAuth(self.api_user, self.api_password),
                timeout=self.timeout,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise WazuhAPIError(f"Authentication to {url} failed: {exc}") from exc

        token = resp.json().get("data", {}).get("token")
        if not token:
            raise WazuhAPIError("Authentication succeeded but no token was returned.")
        self._token = token
        log.info("Obtained Wazuh API JWT.")
        return token

    def _auth_headers(self) -> dict[str, str]:
        if not self._token:
            self.authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    # ------------------------------------------------------------------ #
    # Connectivity / health helpers.
    # ------------------------------------------------------------------ #
    def get_manager_info(self) -> dict[str, Any]:
        """Return manager metadata — handy as a 'is the API alive?' probe."""
        url = f"{self.api_url}/manager/info"
        try:
            resp = self._session.get(url, headers=self._auth_headers(), timeout=self.timeout)
            if resp.status_code == 401:  # token expired -> refresh once
                log.info("Manager token rejected (401); re-authenticating.")
                self._token = None
                resp = self._session.get(url, headers=self._auth_headers(), timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise WazuhAPIError(f"Manager info request failed: {exc}") from exc
        return resp.json().get("data", {}).get("affected_items", [{}])[0]

    def ping(self) -> bool:
        """Best-effort connectivity check used by the dashboard sidebar."""
        try:
            self.get_manager_info()
            return True
        except WazuhAPIError as exc:
            log.warning("Wazuh API ping failed: %s", exc)
            return False

    # ------------------------------------------------------------------ #
    # Alert retrieval from the Indexer (OpenSearch _search API).
    # ------------------------------------------------------------------ #
    def fetch_alerts(self, limit: int | None = None, minutes: int = 240) -> list[dict[str, Any]]:
        """
        Pull the most recent alert documents from the Wazuh Indexer.

        Args:
            limit:   max number of alerts to retrieve (defaults to settings.MAX_ALERTS).
            minutes: only return alerts from the last N minutes.

        Returns:
            A list of alert `_source` dictionaries (the canonical schema).
        """
        limit = limit or settings.MAX_ALERTS
        url = f"{self.indexer_url}/{settings.ALERTS_INDEX}/_search"
        page_size = min(limit, settings.INDEXER_PAGE_SIZE)  # OpenSearch single-page cap

        # Stable sort (timestamp + _id tiebreaker) so `search_after` paginates
        # deterministically beyond the 10k single-page limit.
        sort = [{"timestamp": {"order": "desc"}}, {"_id": {"order": "desc"}}]
        base_query = {"range": {"timestamp": {"gte": f"now-{minutes}m", "lte": "now"}}}

        log.info("Querying Indexer %s (window=%dm, limit=%d)", url, minutes, limit)
        alerts: list[dict[str, Any]] = []
        search_after: Any = None
        while len(alerts) < limit:
            body: Any = {
                "size": min(page_size, limit - len(alerts)),
                "sort": sort,
                "query": base_query,
            }
            if search_after is not None:
                body["search_after"] = search_after
            try:
                resp = self._session.get(
                    url,
                    json=body,
                    auth=HTTPBasicAuth(self.indexer_user, self.indexer_password),
                    timeout=self.timeout,
                )
                resp.raise_for_status()
            except requests.RequestException as exc:
                raise WazuhAPIError(f"Indexer search at {url} failed: {exc}") from exc

            hits = resp.json().get("hits", {}).get("hits", [])
            if not hits:
                break
            alerts.extend(h.get("_source", {}) for h in hits)
            search_after = hits[-1].get("sort")
            if search_after is None or len(hits) < body["size"]:
                break  # no tiebreaker available or last (partial) page reached

        log.info("Fetched %d alerts from the Wazuh Indexer.", len(alerts))
        return alerts


def test_connection() -> bool:
    """Module-level convenience used by the dashboard to verify live access."""
    return WazuhClient().ping()
