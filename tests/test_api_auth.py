"""ISS-017 tests: auth, rate limiting, healthz, error shape."""

from __future__ import annotations

from config import SecuritySettings
from tests.conftest import make_api_settings


async def test_missing_key_401(app_client):
    _, client = app_client
    resp = await client.get("/v1/scans")
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "missing_api_key"


async def test_invalid_key_401(app_client):
    _, client = app_client
    resp = await client.get("/v1/scans", headers={"X-API-Key": "nope"})
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "invalid_api_key"


async def test_valid_key_passes(app_client, user_and_key):
    _, client = app_client
    resp = await client.get("/v1/scans", headers=user_and_key["headers"])
    assert resp.status_code == 200
    assert "items" in resp.json()


async def test_rate_limit_429_with_retry_after(app_client, limited_user_and_key, clean_ratelimits):
    _, client = app_client
    headers = limited_user_and_key["headers"]
    codes = []
    for _ in range(4):
        resp = await client.get("/v1/scans", headers=headers)
        codes.append(resp.status_code)
    assert codes[:2] == [200, 200]
    assert codes[2] == 429
    retry_resp = await client.get("/v1/scans", headers=headers)
    assert retry_resp.status_code == 429
    assert int(retry_resp.headers["Retry-After"]) >= 1


async def test_healthz(app_client):
    _, client = app_client
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] in ("healthy", "degraded")
    assert set(body["checks"]) == {"postgres", "redis"}


async def test_request_id_header(app_client, user_and_key):
    _, client = app_client
    resp = await client.get("/v1/scans", headers=user_and_key["headers"])
    assert resp.headers.get("X-Request-ID")


def test_settings_guard_flag_defaults():
    s = make_api_settings()
    assert s.security.disable_ssrf_guard is False
    assert s.scan.result_cache_ttl_hours == 6
    guarded = make_api_settings(disable_ssrf_guard=True)
    assert guarded.security.disable_ssrf_guard is True
    assert isinstance(guarded.security, SecuritySettings)
