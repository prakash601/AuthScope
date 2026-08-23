"""Shared fixtures: fixture HTTP site, Playwright browser, context manager."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import httpx
import pytest

from engine.browser.context_manager import BrowserContextManager
from engine.page.controller import PageController
from tests.fixtures_site import FixtureSite
from tests.fixtures_site import page as fx_page


@pytest.fixture(scope="session")
def fixture_site():
    site = FixtureSite().start()
    yield site
    site.stop()


@pytest.fixture(scope="session")
async def browser_mgr(fixture_site):
    mgr = BrowserContextManager(timeout_seconds=20)
    await mgr.start()
    yield mgr
    await mgr.stop()


@pytest.fixture
async def scan_context(browser_mgr):
    managed = await browser_mgr.acquire()
    yield managed
    await browser_mgr.release(managed)


@pytest.fixture
def controller():
    return PageController(lazy_captcha_wait_seconds=0)


@pytest.fixture
def url():
    return fx_page


FIXTURES_DIR = Path(__file__).parent / "fixtures"
SIGNATURES_DIR = Path(__file__).parent.parent / "signatures"


# ---------------------------------------------------------------------------
# API fixtures (M3)
# ---------------------------------------------------------------------------

def make_api_settings(disable_ssrf_guard: bool = False):
    """Settings matching the compose environment (.env) so API and workers share
    the same Redis DB — required for result-cache consistency between them."""
    from config import (
        ApiSettings,
        DatabaseSettings,
        EvidenceSettings,
        S3Settings,
        ScanSettings,
        SecuritySettings,
        Settings,
    )

    return Settings(
        database=DatabaseSettings(
            host="localhost", port=5432, user="authscope",
            password="authscope-dev", db="authscope",
        ),
        s3=S3Settings(
            endpoint_url="http://localhost:9000",
            access_key="authscope-dev", secret_key="authscope-dev-secret",
            bucket="authscope-artifacts",
        ),
        scan=ScanSettings(lazy_captcha_wait_seconds=5),
        api=ApiSettings(),
        security=SecuritySettings(disable_ssrf_guard=disable_ssrf_guard),
        evidence=EvidenceSettings(),
        redis_url="redis://localhost:6379/0",
    )


@pytest.fixture(scope="session")
def api_settings():
    return make_api_settings(disable_ssrf_guard=True)


@pytest.fixture(scope="session")
async def app_client(api_settings):
    from api.main import create_app

    app = create_app(api_settings)
    async with app.router.lifespan_context(app), httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        yield app, client


async def _seed_user_key(session_factory, key_hash: str, rate_limit: int = 60) -> str:
    from db.models import ApiKey, User

    user_id = uuid.uuid4()
    async with session_factory() as session, session.begin():
        user = User(id=user_id,
                    email=f"api-{uuid.uuid4().hex[:8]}@authscope.local")
        session.add(user)
        await session.flush()
        session.add(ApiKey(user_id=user.id, key_hash=key_hash,
                           rate_limit_per_minute=rate_limit))
    return str(user_id)


@pytest.fixture(scope="session")
async def user_and_key(app_client):
    app, client = app_client
    raw_key = f"test-key-{uuid.uuid4().hex[:8]}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    user_id = await _seed_user_key(app.state.session_factory, key_hash)
    return {"key": raw_key, "user_id": user_id, "headers": {"X-API-Key": raw_key}}


@pytest.fixture(scope="session")
async def limited_user_and_key(app_client):
    app, _client = app_client
    raw_key = f"limited-{uuid.uuid4().hex[:8]}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    user_id = await _seed_user_key(app.state.session_factory, key_hash,
                                   rate_limit=2)
    return {"key": raw_key, "user_id": user_id, "headers": {"X-API-Key": raw_key}}


@pytest.fixture(scope="session")
async def second_user_and_key(app_client):
    app, client = app_client
    raw_key = f"other-key-{uuid.uuid4().hex[:8]}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    user_id = await _seed_user_key(app.state.session_factory, key_hash)
    return {"key": raw_key, "user_id": user_id, "headers": {"X-API-Key": raw_key}}


@pytest.fixture
async def clean_ratelimits(app_client):
    """Delete rate-limit counters after a test that exercised them."""

    yield
    app, _ = app_client
    keys = [k async for k in app.state.redis.scan_iter("ratelimit:*")]
    if keys:
        await app.state.redis.delete(*keys)
