"""ISS-024 tests: historical diff computation and endpoint."""

from __future__ import annotations

import uuid

import sqlalchemy as sa

from pipeline.diff import Snapshot, compute_diff


def snap(scan_id: str, **kw) -> Snapshot:
    base = dict(
        scan_id=scan_id, created_at="2026-08-23T00:00:00+00:00",
        provider="auth0", flows=["password"], captcha_type="recaptcha_v2_checkbox",
        captcha_visible=True, waf_providers=[], fingerprinting=[],
        has_hsts=True, has_csp=True, has_csrf=True, mfa_detected=False,
        difficulty_score=12, security_score=20,
    )
    base.update(kw)
    return Snapshot(**base)


def test_captcha_vendor_change_detected():
    prev = snap("old")
    cur = snap("new", captcha_type="turnstile_non_interactive", captcha_visible=False)
    diff = compute_diff(cur, prev)
    changed = {c.field: c for c in diff.changes}
    assert "antibot.captcha.type" in changed
    assert changed["antibot.captcha.type"].before == "recaptcha_v2_checkbox"
    assert changed["antibot.captcha.type"].after == "turnstile_non_interactive"
    assert any(c.field == "antibot.captcha.visible" for c in diff.changes)


def test_identical_scans_empty_diff():
    diff = compute_diff(snap("a"), snap("b"))
    assert diff.changes == []


def test_waf_added_removed_and_scores():
    prev = snap("old", waf_providers=["cloudflare"])
    cur = snap("new", waf_providers=["cloudflare", "datadome"],
               difficulty_score=40, security_score=35)
    diff = compute_diff(cur, prev)
    fields = [c.field for c in diff.changes]
    assert "antibot.waf_providers" in fields
    added = next(c for c in diff.changes if c.field == "antibot.waf_providers")
    assert added.after == ["datadome"]
    score = next(c for c in diff.changes if c.field == "difficulty_score")
    assert score.after["delta"] == 28


async def test_diff_endpoint_and_performance(app_client, user_and_key):
    """Two scans with a captcha change + 120-row history; endpoint stays fast."""
    import time as _time

    import sqlalchemy as sa

    _, client = app_client
    session_factory = app_client[0].state.session_factory
    normalized = "https://history.example.com/login"

    async def make_scan(created_offset_s: float, captcha: str | None,
                        visible: bool | None) -> str:
        import datetime as dt

        sid = str(uuid.uuid4())
        created = dt.datetime.now(dt.UTC) - dt.timedelta(
            seconds=created_offset_s)
        async with session_factory() as session, session.begin():
            await session.execute(sa.text(
                "INSERT INTO scans (id, user_id, url, normalized_url, status,"
                " created_at, options) VALUES (:i, :u, :url, :n, 'completed',"
                " :c, '{}')"
            ).bindparams(
                i=uuid.UUID(sid), u=uuid.UUID(user_and_key["user_id"]),
                url=f"https://history.example.com/{sid}", n=normalized,
                c=created,
            ))
            if captcha is not None:
                await session.execute(sa.text(
                    "INSERT INTO antibot_findings (scan_id, captcha_type,"
                    " captcha_visible, waf_providers, fingerprinting_signals,"
                    " cookies_detected, evidence)"
                    " VALUES (:i, :ct, :cv, '{}', '{}', '{}', '{}')"
                ).bindparams(i=uuid.UUID(sid), ct=captcha, cv=visible))
        return sid

    old_id = await make_scan(10 * 86400, "recaptcha_v3_score", False)
    # 120 historical rows inside/around the window (performance padding)
    for k in range(60):
        await make_scan(3600 * (k + 1), "recaptcha_v3_score", False)
        await make_scan(-3600 * (k + 1), "recaptcha_v3_score", False)
    new_id = await make_scan(-1, "turnstile_managed", True)

    started = _time.monotonic()
    resp = await client.get(f"/v1/scans/{new_id}/diff?days=30",
                            headers=user_and_key["headers"])
    elapsed = _time.monotonic() - started
    assert resp.status_code == 200
    body = resp.json()
    assert elapsed < 5.0  # generous CI bound; indexed lookup is ~ms
    assert body["compared_to_scan_id"] != new_id
    changes = {c["field"] for c in body["changes"]}
    assert "antibot.captcha.type" in changes
    change = next(c for c in body["changes"] if c["field"] == "antibot.captcha.type")
    assert change["before"] == "recaptcha_v3_score"
    assert change["after"] == "turnstile_managed"
    assert old_id  # referenced only via window logic


async def test_diff_no_prior_scan_note(app_client, user_and_key):
    _, client = app_client
    sid = str(uuid.uuid4())
    session_factory = app_client[0].state.session_factory
    async with session_factory() as session, session.begin():
        await session.execute(sa.text(
            "INSERT INTO scans (id, user_id, url, normalized_url, status,"
            " created_at, options) VALUES (:i, :u, :url, :n, 'completed',"
            " now(), '{}')"
        ).bindparams(i=uuid.UUID(sid), u=uuid.UUID(user_and_key["user_id"]),
                     url="https://fresh.example.com/l",
                     n="https://fresh.example.com/l"))
    resp = await client.get(f"/v1/scans/{sid}/diff?days=30",
                            headers=user_and_key["headers"])
    assert resp.status_code == 200
    assert resp.json()["changes"] == []
    assert "no prior scan" in resp.json()["note"]
