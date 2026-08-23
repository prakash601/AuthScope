"""ISS-025 tests: feedback submission, stats view, validation."""

from __future__ import annotations

import uuid

import sqlalchemy as sa


async def _create_scan(app, user_and_key) -> str:
    session_factory = app.state.session_factory
    sid = str(uuid.uuid4())
    async with session_factory() as session, session.begin():
        await session.execute(sa.text(
            "INSERT INTO scans (id, user_id, url, normalized_url, status,"
            " created_at, options) VALUES (:i, :u, 'https://fb.example/l',"
            " 'https://fb.example/l', 'completed', now(), '{}')"
        ).bindparams(i=uuid.UUID(sid), u=uuid.UUID(user_and_key["user_id"])))
    return sid


async def test_submit_feedback(app_client, user_and_key):
    app, client = app_client
    scan_id = await _create_scan(app, user_and_key)
    resp = await client.post(
        f"/v1/scans/{scan_id}/feedback",
        json={"finding_kind": "auth", "verdict": "false_positive",
              "signature_name": "onelogin", "comment": "not onelogin"},
        headers=user_and_key["headers"],
    )
    assert resp.status_code == 201
    assert resp.json()["recorded"] is True

    # persisted and queryable
    session_factory = app.state.session_factory
    from db.models import Feedback
    async with session_factory() as session:
        rows = (await session.execute(sa.select(Feedback))).scalars().all()
        assert any(r.signature_name == "onelogin" and r.verdict == "false_positive"
                   for r in rows)


async def test_invalid_verdict_rejected(app_client, user_and_key):
    app, client = app_client
    scan_id = await _create_scan(app, user_and_key)
    resp = await client.post(
        f"/v1/scans/{scan_id}/feedback",
        json={"finding_kind": "auth", "verdict": "maybe"},
        headers=user_and_key["headers"],
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "invalid_verdict"


async def test_invalid_finding_kind_rejected(app_client, user_and_key):
    app, client = app_client
    scan_id = await _create_scan(app, user_and_key)
    resp = await client.post(
        f"/v1/scans/{scan_id}/feedback",
        json={"finding_kind": "nonsense", "verdict": "correct"},
        headers=user_and_key["headers"],
    )
    assert resp.status_code == 422


async def test_unknown_scan_404(app_client, user_and_key):
    _, client = app_client
    resp = await client.post(
        f"/v1/scans/{uuid.uuid4()}/feedback",
        json={"finding_kind": "auth", "verdict": "correct"},
        headers=user_and_key["headers"],
    )
    assert resp.status_code == 404


async def test_stats_view_aggregates_fp_rate(app_client, user_and_key):
    import uuid as _uuid

    app, client = app_client
    scan_id = await _create_scan(app, user_and_key)
    sig = f"turnstile_managed_{_uuid.uuid4().hex[:8]}"  # unique per run
    for verdict in ("correct", "correct", "false_positive"):
        await client.post(
            f"/v1/scans/{scan_id}/feedback",
            json={"finding_kind": "captcha", "signature_name": sig,
                  "verdict": verdict},
            headers=user_and_key["headers"],
        )
    resp = await client.get("/v1/feedback/stats", headers=user_and_key["headers"])
    assert resp.status_code == 200
    row = next(r for r in resp.json() if r["signature_name"] == sig)
    assert row["confirmed"] == 2
    assert row["false_positives"] == 1
    assert abs(row["fp_rate"] - round(1 / 3, 3)) < 0.01
