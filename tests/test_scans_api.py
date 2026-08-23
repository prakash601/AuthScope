"""ISS-018/019 tests: create scan, SSRF guard, cache, retrieval, list filters."""

from __future__ import annotations

import json
import uuid

import httpx
import sqlalchemy as sa
from httpx import AsyncClient

from api.main import create_app
from db.models import Scan
from engine.artifacts import PageArtifact
from engine.detectors.base import Finding
from pipeline.aggregator import aggregate
from pipeline.persist import persist_report
from pipeline.scoring import HeuristicScoring
from tests.conftest import make_api_settings


async def _post_scan(client: AsyncClient, headers, url: str, **opts) -> dict:
    resp = await client.post(
        "/v1/scans", json={"url": url, "options": {"force": False, **opts}}, headers=headers
    )
    return {"status": resp.status_code, "body": resp.json()}


async def test_create_scan_queues_job(app_client, user_and_key):
    _, client = app_client
    result = await _post_scan(client, user_and_key["headers"], "https://queued.example.com/login")
    assert result["status"] == 202
    assert result["body"]["status"] == "queued"
    uuid.UUID(result["body"]["scan_id"])  # valid uuid


async def test_create_rejects_non_http_scheme(app_client, user_and_key):
    _, client = app_client
    result = await _post_scan(client, user_and_key["headers"], "ftp://example.com/login")
    assert result["status"] == 400
    assert result["body"]["detail"]["code"] in ("url_rejected",)


async def test_ssrf_guard_blocks_private_targets(app_client):
    """With the guard enabled (default settings), private targets are rejected."""
    guarded = create_app(make_api_settings())  # guard ON
    transport = httpx.ASGITransport(app=guarded)
    async with guarded.router.lifespan_context(guarded), AsyncClient(
        transport=transport, base_url="http://t"
    ) as client:
        import hashlib as _h

        from tests.conftest import _seed_user_key

        key = f"guard-{uuid.uuid4().hex[:6]}"
        kh = _h.sha256(key.encode()).hexdigest()
        sf = guarded.state.session_factory
        await _seed_user_key(sf, kh)
        for target in (
            "http://169.254.169.254/latest/meta-data",
            "http://127.0.0.1:9000/minio",
            "http://10.0.0.5/internal",
            "http://192.168.1.10/admin",
            "http://localhost:8000/healthz",
        ):
            resp = await client.post("/v1/scans", json={"url": target},
                                     headers={"X-API-Key": key})
            assert resp.status_code == 400, target
            assert resp.json()["detail"]["code"] == "url_rejected"


async def test_result_cache_returns_same_completed_scan(app_client, user_and_key):
    """A completed cached scan is returned directly unless force=true."""
    app, client = app_client
    session_factory = app.state.session_factory
    redis = app.state.redis
    from workers.tasks import result_cache_key

    url = "https://cached.example.com/login"
    normalized = url
    sid = str(uuid.uuid4())
    async with session_factory() as session, session.begin():
        session.add(
            Scan(id=uuid.UUID(sid), user_id=uuid.UUID(user_and_key["user_id"]),
                 url=url, normalized_url=normalized, status="completed",
                 difficulty_score=42)
        )
    await redis.set(result_cache_key(normalized), sid, ex=600)

    first = await _post_scan(client, user_and_key["headers"], url)
    assert first["body"]["scan_id"] == sid and first["body"]["cached"] is True

    forced = await _post_scan(client, user_and_key["headers"], url, force=True)
    assert forced["body"]["scan_id"] != sid and forced["body"]["cached"] is False


async def test_get_unknown_scan_404(app_client, user_and_key):
    _, client = app_client
    resp = await client.get(f"/v1/scans/{uuid.uuid4()}",
                            headers=user_and_key["headers"])
    assert resp.status_code == 404


async def test_ownership_enforced(app_client, user_and_key, second_user_and_key):
    _, client = app_client
    created = await _post_scan(client, user_and_key["headers"], "https://own.example.com/l")
    sid = created["body"]["scan_id"]
    resp = await client.get(f"/v1/scans/{sid}", headers=second_user_and_key["headers"])
    assert resp.status_code == 404  # no information leak


async def test_full_report_matches_schema(app_client, user_and_key):
    """Persist a complete report via the pipeline, then GET it back."""
    app, client = app_client

    from engine.artifacts import PageArtifact
    from engine.detectors.base import Finding, MatchedSignal
    from pipeline.aggregator import aggregate
    from pipeline.persist import persist_report
    from pipeline.scoring import HeuristicScoring

    _, client = app_client
    created = await _post_scan(client, user_and_key["headers"], "https://report.example.com/l")
    scan_id = created["body"]["scan_id"]
    session_factory = app.state.session_factory

    findings = [
        Finding(kind="auth_provider", name="auth0", provider="auth0", confidence=0.95,
                matched_signals=[MatchedSignal(signal_type="script_src",
                                               value="cdn.auth0.com/x.js")],
                extra={"flows": ["password", "oauth_code"]}),
        Finding(kind="captcha", name="recaptcha_v3_score", confidence=0.9,
                extra={"visible": False, "score_based": True}),
        Finding(kind="waf", name="cloudflare", provider="cloudflare", confidence=0.9,
                matched_signals=[MatchedSignal(signal_type="cookie", value="__cf_bm")]),
    ]
    report, _ = aggregate(scan_id, "https://report.example.com/l", PageArtifact(url="https://report.example.com/l"),
                          findings, HeuristicScoring())
    report.artifacts.har_url = None  # no evidence upload in this test
    async with session_factory() as session, session.begin():
        await persist_report(session, report)

    resp = await client.get(f"/v1/scans/{scan_id}", headers=user_and_key["headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["auth"]["provider"] == "auth0"
    assert body["antibot"]["captcha"]["type"] == "recaptcha_v3_score"
    assert body["antibot"]["waf_providers"] == ["cloudflare"]
    assert body["antibot"]["difficulty_score"] > 0

    with open("schemas/report.schema.json") as fh:
        schema = json.load(fh)
    import jsonschema
    # artifacts URLs differ (presigned) — validate core sections against schema
    subset = {k: body[k] for k in ("scan_id", "url", "status", "created_at", "auth",
                                   "security", "antibot")}
    jsonschema.validate(subset, schema)


async def test_list_filters_and_pagination(app_client, user_and_key):
    app, client = app_client
    session_factory = app.state.session_factory

    findings = [Finding(kind="auth_provider", name="okta", provider="okta",
                        confidence=0.9)]
    ids = []
    for score in (10, 80):
        sid = str(uuid.uuid4())
        ids.append(sid)
        artifact = PageArtifact(url=f"https://list-{score}.example.com/login")
        report, _ = aggregate(sid, artifact.url, artifact,
                              findings if score == 80 else [], HeuristicScoring())
        report.url = artifact.url
        async with session_factory() as session, session.begin():
            session.add(Scan(id=uuid.UUID(sid),
                             user_id=uuid.UUID(user_and_key["user_id"]),
                             url=artifact.url, normalized_url=artifact.url,
                             status="completed"))
            await persist_report(session, report)
            await session.execute(
                sa.update(Scan).where(Scan.id == uuid.UUID(sid))
                .values(difficulty_score=score)
            )

    resp = await client.get("/v1/scans?min_difficulty=50&limit=100",
                            headers=user_and_key["headers"])
    items = resp.json()["items"]
    assert all((it["difficulty_score"] or 0) >= 50 for it in items)
    assert any(it["scan_id"] == ids[1] for it in items)
    assert not any(it["scan_id"] == ids[0] for it in items)

    resp2 = await client.get("/v1/scans?provider=okta&limit=100",
                             headers=user_and_key["headers"])
    okta_items = resp2.json()["items"]
    assert any(it["scan_id"] == ids[1] for it in okta_items)
    assert not any(it["scan_id"] == ids[0] for it in okta_items)
