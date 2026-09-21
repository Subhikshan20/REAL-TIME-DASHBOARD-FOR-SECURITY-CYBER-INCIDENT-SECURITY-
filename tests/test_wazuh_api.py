"""
Tests for the Wazuh API client (wazuh_api.py).

The HTTP session is mocked so the auth/fetch/refresh logic is verified without a
live Wazuh instance.
"""

from unittest.mock import MagicMock

import pytest
import requests

import wazuh_api


class FakeResp:
    def __init__(self, json_data=None, status_code=200, raise_exc=None):
        self._json = json_data or {}
        self.status_code = status_code
        self._raise = raise_exc

    def json(self):
        return self._json

    def raise_for_status(self):
        if self._raise:
            raise self._raise


@pytest.fixture
def client():
    c = wazuh_api.WazuhClient(
        api_url="https://wazuh:55000",
        api_user="u",
        api_password="p",
        indexer_url="https://wazuh:9200",
        indexer_user="iu",
        indexer_password="ip",
    )
    c._session = MagicMock()
    return c


def test_authenticate_returns_token(client):
    client._session.post.return_value = FakeResp({"data": {"token": "JWT123"}})
    assert client.authenticate() == "JWT123"
    assert client._token == "JWT123"


def test_authenticate_missing_token_raises(client):
    client._session.post.return_value = FakeResp({"data": {}})
    with pytest.raises(wazuh_api.WazuhAPIError):
        client.authenticate()


def test_authenticate_network_error_raises(client):
    client._session.post.side_effect = requests.RequestException("connection refused")
    with pytest.raises(wazuh_api.WazuhAPIError):
        client.authenticate()


def test_fetch_alerts_returns_sources(client):
    client._token = "JWT123"
    hits = {
        "hits": {"hits": [{"_source": {"rule": {"id": "1"}}}, {"_source": {"rule": {"id": "2"}}}]}
    }
    client._session.get.return_value = FakeResp(hits)
    alerts = client.fetch_alerts(minutes=60)
    assert [a["rule"]["id"] for a in alerts] == ["1", "2"]


def test_fetch_alerts_error_raises(client):
    client._token = "JWT123"
    client._session.get.side_effect = requests.RequestException("indexer down")
    with pytest.raises(wazuh_api.WazuhAPIError):
        client.fetch_alerts()


def test_fetch_alerts_paginates_with_search_after(client, monkeypatch):
    client._token = "JWT123"
    monkeypatch.setattr(wazuh_api.settings, "INDEXER_PAGE_SIZE", 2)

    def page(ids):
        return FakeResp(
            {"hits": {"hits": [{"_source": {"rule": {"id": i}}, "sort": [i]} for i in ids]}}
        )

    # Three pages (2, 2, 1) consumed via search_after.
    client._session.get.side_effect = [page(["1", "2"]), page(["3", "4"]), page(["5"])]
    alerts = client.fetch_alerts(limit=5)
    assert [a["rule"]["id"] for a in alerts] == ["1", "2", "3", "4", "5"]
    assert client._session.get.call_count == 3


def test_manager_info_refreshes_token_on_401(client):
    # First GET -> 401, then re-auth (POST), then second GET -> 200.
    client._token = "EXPIRED"
    ok = FakeResp({"data": {"affected_items": [{"version": "4.x"}]}})
    unauthorized = FakeResp({}, status_code=401)
    client._session.get.side_effect = [unauthorized, ok]
    client._session.post.return_value = FakeResp({"data": {"token": "FRESH"}})

    info = client.get_manager_info()
    assert info == {"version": "4.x"}
    assert client._token == "FRESH"
    assert client._session.get.call_count == 2


def test_ping_returns_false_on_failure(client):
    client._session.get.side_effect = requests.RequestException("down")
    client._session.post.return_value = FakeResp({"data": {"token": "X"}})
    assert client.ping() is False
