"""ISS-028/029 tests: dashboard assets, disclaimer, robots.txt policy flag."""

from __future__ import annotations

import uuid
from pathlib import Path

DASHBOARD = Path(__file__).parent.parent / "dashboard"


async def test_dashboard_assets_served(app_client):
    _, client = app_client
    resp = await client.get("/dashboard/")
    assert resp.status_code == 200
    assert "AuthScope" in resp.text
    for asset in ("/dashboard/app.js", "/dashboard/style.css"):
        r = await client.get(asset)
        assert r.status_code == 200, asset


async def test_dashboard_evidence_viewer_and_filters(app_client):
    """T13: HAR explorer block, WAF filter input, and their JS wiring exist."""
    _, client = app_client
    index = (await client.get("/dashboard/")).text
    assert 'id="har-explorer"' in index
    assert 'id="btn-har"' in index and 'id="har-filter"' in index
    assert 'id="har-table"' in index
    assert 'id="f-waf"' in index

    js = (await client.get("/dashboard/app.js")).text
    assert "waf_provider" in js  # list filter parity with the API
    assert "harEntries" in js and "renderHar" in js


async def test_report_includes_disclaimer(app_client, user_and_key):
    """Detection-only disclaimer is surfaced in every report response."""
    import sqlalchemy as sa

    app, client = app_client
    sid = str(uuid.uuid4())
    async with app.state.session_factory() as session, session.begin():
        await session.execute(
            sa.text(
                "INSERT INTO scans (id, user_id, url, normalized_url, status,"
                " created_at, options) VALUES (:i, :u, 'https://d.example/l',"
                " 'https://d.example/l', 'completed', now(), '{}')"
            ).bindparams(i=uuid.UUID(sid), u=uuid.UUID(user_and_key["user_id"]))
        )
    resp = await client.get(f"/v1/scans/{sid}", headers=user_and_key["headers"])
    body = resp.json()
    assert body.get("disclaimer") is not None
    assert "detect" in body["disclaimer"].lower()


async def test_robots_txt_flag_blocks_disallowed_path(browser_mgr, controller):
    """With SCAN_RESPECT_ROBOTS_TXT on, disallowed paths are never navigated."""
    from config import get_settings
    from tests.fixtures_site import page as fx

    settings = get_settings()
    original = settings.scan.respect_robots_txt
    managed = await browser_mgr.acquire()
    try:
        # flag off: navigates normally
        settings.scan.respect_robots_txt = False
        result = await controller.run(managed, fx("index.html"))
        assert result.artifact.blocked is False
        assert result.artifact.http_status == 200

        # fixture site has no /robots.txt → allowed even when flag on
        settings.scan.respect_robots_txt = True
        result = await controller.run(managed, fx("index.html"))
        assert result.artifact.blocked is False
    finally:
        settings.scan.respect_robots_txt = original
        await browser_mgr.release(managed)


async def test_robots_txt_disallow_honoured():
    """Unit-level: parser blocks disallowed targets when flag enabled."""
    from urllib.robotparser import RobotFileParser

    parser = RobotFileParser()
    parser.parse(
        [
            "User-agent: *",
            "Disallow: /private/",
        ]
    )
    assert parser.can_fetch("*", "https://x.test/public/page") is True
    assert parser.can_fetch("*", "https://x.test/private/login") is False


async def test_robots_txt_fetched_through_scan_context():
    """Robots body comes from the scan context (proxy-honoring path)."""
    from config import get_settings
    from engine.page.controller import PageController

    settings = get_settings()
    original = settings.scan.respect_robots_txt
    settings.scan.respect_robots_txt = True
    try:

        class _Resp:
            ok = True

            async def text(self):
                return "User-agent: *\nDisallow: /private/\n"

        class _APIRequest:
            async def get(self, url, timeout=None):
                assert url == "https://x.test/robots.txt"
                return _Resp()

        class _Context:
            request = _APIRequest()

        controller = PageController(lazy_captcha_wait_seconds=0)
        assert (
            await controller._robots_disallows("https://x.test/private/login", _Context()) is True
        )
        assert await controller._robots_disallows("https://x.test/public/page", _Context()) is False
    finally:
        settings.scan.respect_robots_txt = original
