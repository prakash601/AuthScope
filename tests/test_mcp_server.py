"""T16 tests: AuthScope MCP server tools wired to the real API.

The tools talk to the API in-process via ``httpx.ASGITransport`` so the whole
path (MCP tool -> client -> FastAPI -> eager worker) is exercised.
"""

from __future__ import annotations

import json

import httpx
import pytest

from mcp_server import server
from mcp_server.client import AuthScopeClient, AuthScopeError
from tests.fixtures_site import page as fx

EXPECTED_TOOLS = {
    "health",
    "create_scan",
    "get_scan",
    "wait_for_scan",
    "scan_and_wait",
    "list_scans",
    "get_diff",
    "bulk_scan",
    "bulk_progress",
    "submit_feedback",
    "feedback_stats",
}


@pytest.fixture(autouse=True)
def _site_running(fixture_site):
    """Scans navigate fixture pages; ensure the site is up."""
    yield


@pytest.fixture(scope="session")
def eager_celery():
    """Run Celery tasks inline for tests."""
    from workers.celery_app import celery_app

    celery_app.conf.update(
        task_always_eager=True,
        task_store_eager_result=True,
        task_eager_propagates=True,
    )
    yield celery_app
    celery_app.conf.task_always_eager = False


@pytest.fixture
def install_client(app_client, user_and_key, monkeypatch):
    """Point the MCP tools at the in-process API app with a valid key."""
    app, _ = app_client
    key = user_and_key["key"]

    def _build(api_key: str | None = None) -> AuthScopeClient:
        return AuthScopeClient(
            api_key=api_key if api_key is not None else key,
            base_url="http://testserver",
            transport=httpx.ASGITransport(app=app),
        )

    monkeypatch.setattr(server, "get_client", _build)
    return _build


async def test_tool_registry_exposes_expected_tools():
    tools = await server.mcp.list_tools()
    assert {t.name for t in tools} >= EXPECTED_TOOLS


async def test_health_reports_api_and_valid_key(install_client):
    out = await server.health()
    assert out["auth"] == "ok"
    assert out["service"]["status"] in {"healthy", "degraded"}


async def test_missing_api_key_is_actionable(monkeypatch):
    monkeypatch.delenv("AUTHSCOPE_API_KEY", raising=False)
    client = AuthScopeClient(api_key="")
    with pytest.raises(AuthScopeError) as excinfo:
        await client.list_scans(limit=1)
    assert excinfo.value.code == "missing_api_key"
    assert "AUTHSCOPE_API_KEY" in str(excinfo.value)


async def test_invalid_api_key_maps_to_401(install_client):
    client = install_client("not-a-real-key")
    with pytest.raises(AuthScopeError) as excinfo:
        await client.list_scans(limit=1)
    assert excinfo.value.status == 401
    assert "AUTHSCOPE_API_KEY" in str(excinfo.value)


async def test_scan_and_wait_end_to_end(install_client, eager_celery):
    out = await server.scan_and_wait(fx("auth0_like.html"), timeout_s=60)
    assert out["summary"]["status"] == "completed"
    assert out["summary"]["auth"]["provider"] == "auth0"
    assert out["cached"] is False


async def test_get_scan_returns_summary_and_optional_raw(install_client, eager_celery):
    created = await server.create_scan(fx("turnstile_visible.html"))
    scan_id = created["scan_id"]
    assert created["status"] in {"queued", "running", "completed"}

    summary = await server.get_scan(scan_id)
    assert summary["summary"]["scan_id"] == scan_id
    assert "report" not in summary

    raw = await server.get_scan(scan_id, include_raw=True)
    assert raw["report"]["scan_id"] == scan_id
    assert "disclaimer" in raw["report"]


async def test_list_scans_filters_by_provider(install_client, eager_celery):
    await server.scan_and_wait(fx("auth0_like.html"), timeout_s=60)
    out = await server.list_scans(provider="auth0", limit=5)
    assert out["total"] >= 1
    assert all(item["status"] in {"completed", "waf_blocked", "failed"} for item in out["items"])


async def test_bulk_scan_and_progress(install_client, eager_celery):
    csv_body = "url\n" + fx("auth0_like.html") + "\n" + fx("index.html")
    created = await server.bulk_scan(csv_body)
    assert created["accepted"] == 2
    progress = await server.bulk_progress(created["batch_id"])
    assert progress["total"] == 2
    assert sum(progress["by_status"].values()) == 2


async def test_get_diff_without_prior_scan(install_client, eager_celery):
    created = await server.create_scan(fx("index.html"))
    diff = await server.get_diff(created["scan_id"], days=30)
    assert diff["scan_id"] == created["scan_id"]
    assert isinstance(diff["changes"], list)


async def test_submit_feedback_and_stats(install_client, eager_celery):
    created = await server.scan_and_wait(fx("auth0_like.html"), timeout_s=60)
    scan_id = created["summary"]["scan_id"]
    recorded = await server.submit_feedback(
        scan_id, finding_kind="auth", verdict="false_positive", signature_name="auth0"
    )
    assert recorded["recorded"] is True
    assert recorded["verdict"] == "false_positive"
    stats = await server.feedback_stats()
    assert isinstance(stats, list)


async def test_rate_limited_key_maps_to_429(
    app_client, limited_user_and_key, clean_ratelimits, monkeypatch
):
    app, _ = app_client
    client = AuthScopeClient(
        api_key=limited_user_and_key["key"],
        base_url="http://testserver",
        transport=httpx.ASGITransport(app=app),
    )
    for _ in range(2):
        await client.list_scans(limit=1)
    with pytest.raises(AuthScopeError) as excinfo:
        await client.list_scans(limit=1)
    assert excinfo.value.status == 429
    assert "Rate limited" in str(excinfo.value)


async def test_wait_for_scan_timeout(install_client, monkeypatch):
    """A scan that never finishes returns the last status, not a hang."""
    client = install_client()

    async def _always_running(scan_id: str):
        return {"scan_id": scan_id, "status": "running", "cached": False}

    monkeypatch.setattr(client, "get_scan", _always_running)
    monkeypatch.setattr(server, "get_client", lambda: client)
    out = await server.wait_for_scan("stuck-scan", timeout_s=0.3, poll_s=0.1)
    assert out["timed_out"] is True
    assert out["status"] == "running"


async def test_tool_output_never_leaks_api_key(install_client, user_and_key):
    out = await server.health()
    assert user_and_key["key"] not in json.dumps(out)
    assert user_and_key["key"] not in json.dumps(await server.list_scans(limit=1))


async def _ok_app(scope, receive, send):
    if scope["type"] == "http":
        from starlette.responses import PlainTextResponse

        await PlainTextResponse("ok")(scope, receive, send)


async def test_bearer_guard_enforces_token():
    guarded = server.BearerTokenGuard(_ok_app, "s3cret")
    transport = httpx.ASGITransport(app=guarded)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.post("/mcp")).status_code == 401
        denied = await client.post("/mcp", headers={"Authorization": "Bearer wrong"})
        assert denied.status_code == 401
        allowed = await client.post("/mcp", headers={"Authorization": "Bearer s3cret"})
        assert allowed.status_code == 200


def test_run_http_refuses_non_loopback_without_optin():
    with pytest.raises(SystemExit):
        server.run_http("http", "0.0.0.0", 8765, None, allow_remote=False)


def test_run_http_requires_token_when_allowing_remote():
    with pytest.raises(SystemExit):
        server.run_http("http", "0.0.0.0", 8765, None, allow_remote=True)


def test_is_loopback():
    assert server._is_loopback("127.0.0.1")
    assert server._is_loopback("localhost")
    assert not server._is_loopback("0.0.0.0")
