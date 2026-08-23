"""ISS-004 acceptance: model round-trip against live Postgres.

Skips (with message) when the compose Postgres isn't reachable so unit-only
runs stay green; CI / dev with `make compose-up` exercises the real path.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from sqlalchemy import orm

from config import get_settings
from db.models import (
    AntibotFinding,
    ApiKey,
    Artifacts,
    AuthFinding,
    Feedback,
    Scan,
    SecurityFinding,
    Signature,
    User,
    Webhook,
)


async def _reachable() -> bool:
    try:
        from sqlalchemy.ext.asyncio import create_async_engine

        engine = create_async_engine(get_settings().database.async_url)
        try:
            async with engine.connect():
                return True
        finally:
            await engine.dispose()
    except Exception:  # noqa: BLE001
        return False


@pytest.fixture
async def db_session():
    if not await _reachable():
        pytest.skip("Postgres not reachable — run `make compose-up`")
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    settings = get_settings()
    engine = create_async_engine(settings.database.async_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
        await session.rollback()
    await engine.dispose()


async def test_full_round_trip(db_session) -> None:
    session = db_session
    run_id = uuid.uuid4().hex[:8]
    scan_id = uuid.uuid4()

    user = User(email=f"rt-{uuid.uuid4().hex[:8]}@authscope.local")
    session.add(user)
    await session.flush()
    session.add(ApiKey(user_id=user.id, key_hash=uuid.uuid4().hex, label="test"))
    scan = Scan(
        id=scan_id,
        user_id=user.id,
        url="https://example.com/login",
        normalized_url="https://example.com/login",
        status="completed",
        difficulty_score=78,
        security_score=34,
        options={"deep_scan": True},
        completed_at=datetime.now(UTC),
    )
    session.add(scan)
    await session.flush()
    session.add_all(
        [
            AuthFinding(
                scan_id=scan_id,
                provider="auth0",
                flow=["oauth_code", "password"],
                confidence=0.97,
                evidence={"matched_signals": [{"type": "script_src"}]},
            ),
            SecurityFinding(
                scan_id=scan_id,
                has_csrf=True,
                has_hsts=True,
                has_csp=False,
                cookie_flags={"sess": {"secure": True, "httponly": True}},
                mfa_detected=True,
                raw_headers={"strict-transport-security": "max-age=31536000"},
            ),
            AntibotFinding(
                scan_id=scan_id,
                captcha_type="turnstile_invisible",
                captcha_visible=False,
                waf_providers=["cloudflare"],
                fingerprinting_signals=["fingerprintjs_pro"],
                cookies_detected=["__cf_bm"],
                evidence={},
            ),
            Artifacts(
                scan_id=scan_id,
                har_url="s3://bucket/scan/har.json",
                screenshot_url="s3://bucket/scan/page.png",
            ),
            Feedback(
                scan_id=scan_id,
                finding_kind="auth",
                signature_name="auth0",
                verdict="correct",
            ),
            Webhook(user_id=user.id, url="https://hooks.example/x", secret="s3cret"),
            Signature(
                category="antibot",
                name=f"cloudflare_turnstile_{run_id}",
                yaml_definition={"signals": {"dom": "cf-turnstile"}},
                version=1,
            ),
        ]
    )
    await session.flush()

    loaded = (
        await session.execute(
            sa.select(Scan)
            .options(
                orm.selectinload(Scan.auth_finding),
                orm.selectinload(Scan.security_finding),
                orm.selectinload(Scan.antibot_finding),
                orm.selectinload(Scan.artifacts),
            )
            .where(Scan.id == scan_id)
        )
    ).scalar_one()
    assert loaded.status == "completed"
    assert loaded.auth_finding.provider == "auth0"
    assert loaded.auth_finding.flow == ["oauth_code", "password"]
    assert loaded.auth_finding.confidence == pytest.approx(0.97)
    assert loaded.security_finding.cookie_flags["sess"]["secure"] is True
    assert loaded.antibot_finding.waf_providers == ["cloudflare"]
    assert loaded.antibot_finding.captcha_type == "turnstile_invisible"
    assert loaded.artifacts.har_url.endswith("har.json")
    assert loaded.options == {"deep_scan": True}

    sig = (
        await session.execute(
            sa.select(Signature).where(Signature.name == f"cloudflare_turnstile_{run_id}")
        )
    ).scalar_one()
    assert sig.yaml_definition["signals"]["dom"] == "cf-turnstile"
