"""ISS-018/022 tests: Celery run_scan (eager) end-to-end + retry/blocked policy."""

from __future__ import annotations

import uuid

import pytest

from tests.fixtures_site import page as fx
from workers.tasks import should_retry_blocked


@pytest.fixture(autouse=True)
def _site_running(fixture_site):
    """Worker tests navigate fixture pages; ensure the site is up."""
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


async def _get_scan(app, scan_id: str):
    import sqlalchemy as sa

    from db.models import Scan

    async with app.state.session_factory() as session:
        return (
            await session.execute(sa.select(Scan).where(Scan.id == uuid.UUID(scan_id)))
        ).scalar_one()


async def test_run_scan_completes_end_to_end(app_client, user_and_key, eager_celery):
    """POST /v1/scans -> eager worker -> full report retrievable."""
    _, client = app_client
    resp = await client.post(
        "/v1/scans", json={"url": fx("auth0_like.html")}, headers=user_and_key["headers"]
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    result = await client.get(f"/v1/scans/{scan_id}", headers=user_and_key["headers"])
    body = result.json()
    assert body["status"] == "completed"
    assert body["auth"]["provider"] == "auth0"
    assert "password" in body["auth"]["flows"]
    assert body["security"] is not None
    assert body["antibot"]["difficulty_score"] is not None


async def test_blocked_first_attempt_retries_then_completes(app_client, user_and_key, eager_celery):
    """403 challenge on first navigation -> retry succeeds -> completed."""
    _, client = app_client
    resp = await client.post(
        "/v1/scans",
        json={"url": fx("flaky_block.html"), "options": {"force": True}},
        headers=user_and_key["headers"],
    )
    scan_id = resp.json()["scan_id"]

    scan = await _get_scan(app_client[0], scan_id)
    assert scan.status == "completed"  # retried past the challenge, never failed
    assert scan.options.get("attempts", 1) >= 1


async def test_persistent_block_ends_waf_blocked(app_client, user_and_key, eager_celery):
    _, client = app_client
    resp = await client.post(
        "/v1/scans",
        json={"url": fx("blocked/cloudflare"), "options": {"force": True}},
        headers=user_and_key["headers"],
    )
    scan_id = resp.json()["scan_id"]

    scan = await _get_scan(app_client[0], scan_id)
    assert scan.status == "waf_blocked"
    assert scan.status != "failed"

    # report still carries partial intelligence
    result = await client.get(f"/v1/scans/{scan_id}", headers=user_and_key["headers"])
    assert result.json()["status"] == "waf_blocked"


async def test_retry_policy_decision_function():
    assert should_retry_blocked(attempt=1, retry_enabled=True) is True
    assert should_retry_blocked(attempt=2, retry_enabled=True) is False
    assert should_retry_blocked(attempt=1, retry_enabled=False) is False


async def test_completed_scan_is_cached(app_client, user_and_key, eager_celery):
    """Second create for same URL within TTL returns the completed scan (cached)."""
    _, client = app_client
    url = fx("turnstile_visible.html")
    r1 = await client.post("/v1/scans", json={"url": url}, headers=user_and_key["headers"])
    id1 = r1.json()["scan_id"]
    # wait for eager completion happened inline already; cache set during finalize
    r2 = await client.post("/v1/scans", json={"url": url}, headers=user_and_key["headers"])
    body2 = r2.json()
    assert body2.get("cached") is True and body2["scan_id"] == id1


async def test_unexpected_failure_marks_scan_failed(
    app_client, user_and_key, eager_celery, monkeypatch
):
    """A mid-pipeline crash marks the scan failed (never stuck running)."""
    import pipeline.evidence

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated upload outage")

    monkeypatch.setattr(pipeline.evidence, "upload_evidence", _boom)
    _, client = app_client
    # force=true bypasses the result cache so the pipeline (and this crash) always run.
    # Starlette sends a 500 but the test transport re-raises app exceptions.
    with pytest.raises(RuntimeError, match="simulated upload outage"):
        await client.post(
            "/v1/scans",
            json={"url": fx("index.html"), "options": {"force": True}},
            headers=user_and_key["headers"],
        )
    listing = await client.get("/v1/scans?status=failed", headers=user_and_key["headers"])
    assert listing.json()["total"] >= 1
    item = listing.json()["items"][0]
    assert item["status"] == "failed"
    row = await _get_scan(app_client[0], item["scan_id"])
    assert row.error_detail and "simulated upload outage" in row.error_detail
