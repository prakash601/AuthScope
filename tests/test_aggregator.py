"""ISS-015 tests: aggregation, tie-breaks, schema validation, persistence round-trip."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.artifacts import PageArtifact
from engine.detectors.base import Finding, MatchedSignal
from pipeline.aggregator import aggregate
from pipeline.scoring import HeuristicScoring

SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "report.schema.json"
STRAT = HeuristicScoring()


def make_artifact(**kw) -> PageArtifact:
    return PageArtifact(url="https://x.test/login", **kw)


def auth_finding(name: str, n_signals: int, confidence: float) -> Finding:
    return Finding(
        kind="auth_provider",
        name=name,
        provider=name,
        confidence=confidence,
        matched_signals=[
            MatchedSignal(signal_type="script_src", value=f"sig-{i}") for i in range(n_signals)
        ],
        extra={"flows": ["password"]} if n_signals else {},
    )


def test_conflict_resolution_prefers_specificity():
    """Vendor-specific beats generic even with fewer signals (documented tie-break)."""
    generic = Finding(
        kind="auth_provider",
        name="generic_oidc_wellknown",
        provider="generic_oidc_wellknown",
        confidence=0.42,
        matched_signals=[MatchedSignal(signal_type="network", value="x")],
    )
    vendor = Finding(
        kind="auth_provider",
        name="auth0",
        provider="auth0",
        confidence=0.63,
        matched_signals=[MatchedSignal(signal_type="script_src", value="cdn.auth0.com")],
        extra={"flows": ["password"]},
    )
    report, _ = aggregate("s1", "https://x.test", make_artifact(), [generic, vendor], STRAT)
    assert report.auth.provider == "auth0"
    assert report.auth.other_providers == ["generic_oidc_wellknown"]


def test_tie_break_signal_count_then_confidence_then_name():
    a = auth_finding("alpha", 2, 0.7)
    b = auth_finding("beta", 2, 0.8)
    report, _ = aggregate("s1", "https://x.test", make_artifact(), [a, b], STRAT)
    assert report.auth.provider == "beta"  # same signals -> higher confidence wins

    c = auth_finding("gamma", 3, 0.6)
    d = auth_finding("delta", 2, 0.9)
    report2, _ = aggregate("s2", "https://x.test", make_artifact(), [c, d], STRAT)
    assert report2.auth.provider == "gamma"  # more independent signals win

    e = auth_finding("zeta", 1, 0.7)
    g = auth_finding("alpha", 1, 0.7)
    report3, _ = aggregate("s3", "https://x.test", make_artifact(), [e, g], STRAT)
    assert report3.auth.provider == "alpha"  # full tie -> alphabetical determinism


def test_waf_and_fingerprinting_collected_additively():
    findings = [
        Finding(
            kind="waf",
            name="cloudflare",
            provider="cloudflare",
            confidence=0.9,
            matched_signals=[MatchedSignal(signal_type="cookie", value="__cf_bm")],
        ),
        Finding(kind="waf", name="datadome", provider="datadome", confidence=0.85),
        Finding(kind="fingerprinting", name="castle", provider=None, confidence=0.9),
        Finding(
            kind="captcha",
            name="recaptcha_v3_score",
            confidence=0.9,
            extra={"visible": False, "score_based": True},
        ),
    ]
    report, scores = aggregate("s4", "https://x.test", make_artifact(), findings, STRAT)
    assert report.antibot.waf_providers == ["cloudflare", "datadome"]
    assert report.antibot.fingerprinting_signals == ["castle"]
    assert report.antibot.cookies_detected == ["__cf_bm"]
    assert report.antibot.captcha.type == "recaptcha_v3_score"
    assert report.antibot.captcha.score_based is True
    assert report.antibot.difficulty_reasoning.startswith("Score ")
    assert scores.difficulty_score == report.antibot.difficulty_score


def test_report_validates_against_committed_schema():
    schema = json.loads(SCHEMA_PATH.read_text())
    import jsonschema

    findings = [
        auth_finding("auth0", 3, 0.95),
        security_posture(),
        Finding(
            kind="captcha",
            name="turnstile_managed",
            confidence=0.94,
            extra={"visible": True, "score_based": False},
        ),
        Finding(
            kind="waf",
            name="cloudflare",
            provider="cloudflare",
            confidence=0.9,
            matched_signals=[MatchedSignal(signal_type="header", value="server: cloudflare")],
        ),
    ]
    report, _ = aggregate(
        "7b9c0f2a-0000-0000-0000-000000000000",
        "https://x.test/login",
        make_artifact(),
        findings,
        STRAT,
    )
    jsonschema.validate(report.model_dump(mode="json"), schema)


def test_committed_schema_matches_model():
    """CI drift guard: regen with `ScanReport.model_json_schema()` on change.

    The committed file carries a hand-set `$id` + title; both are ignored here —
    structure is what must stay in sync.
    """
    from pipeline.aggregator import ScanReport

    fresh = ScanReport.model_json_schema()
    committed = json.loads(SCHEMA_PATH.read_text())
    committed.pop("$id", None)
    fresh["title"] = committed.get("title", fresh.get("title"))
    assert fresh == committed


def security_posture() -> Finding:
    return Finding(
        kind="security",
        name="posture",
        confidence=0.95,
        extra={
            "has_csrf": True,
            "has_hsts": True,
            "has_csp": False,
            "cookie_flags": {"issues": {}},
            "mfa_detected": False,
            "raw_headers": {"server": "nginx"},
            "missing_security_headers": ["content-security-policy"],
            "has_permissions_policy": False,
        },
    )


# ---------------------------------------------------------------------------
# Persistence round-trip against live Postgres + MinIO
# ---------------------------------------------------------------------------


async def _deps_reachable() -> bool:
    try:
        from sqlalchemy.ext.asyncio import create_async_engine

        from config import get_settings
        from pipeline.evidence import make_client

        settings = get_settings()
        engine = create_async_engine(settings.database.async_url)
        try:
            async with engine.connect():
                pass
        finally:
            await engine.dispose()
        client = make_client()
        client.head_bucket(Bucket=settings.s3.bucket)
        return True
    except Exception:  # noqa: BLE001
        return False


@pytest.fixture
async def infra():
    if not await _deps_reachable():
        pytest.skip("Postgres/MinIO not reachable — run `make compose-up`")
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from config import get_settings

    settings = get_settings()
    engine = create_async_engine(settings.database.async_url)
    yield {
        "factory": async_sessionmaker(engine, expire_on_commit=False),
        "engine": engine,
        "settings": settings,
    }
    await engine.dispose()


async def test_full_round_trip_db_and_evidence(infra):
    import uuid

    import sqlalchemy as sa

    from db.models import (
        AntibotFinding,
        ApiKey,
        Artifacts,
        AuthFinding,
        Scan,
        SecurityFinding,
        User,
    )
    from pipeline.evidence import download, make_client, upload_evidence
    from pipeline.persist import persist_report

    scan_id = str(uuid.uuid4())

    # seed scan row + user for FK integrity
    async with infra["factory"]() as session, session.begin():
        user = User(email=f"agg-{uuid.uuid4().hex[:8]}@authscope.local")
        session.add(user)
        await session.flush()
        session.add(ApiKey(user_id=user.id, key_hash=uuid.uuid4().hex))
        session.add(
            Scan(
                id=uuid.UUID(scan_id),
                user_id=user.id,
                url="https://roundtrip.test/login",
                normalized_url="https://roundtrip.test/login",
                status="running",
            )
        )

    # build findings via real detectors path: aggregate from hand-made set
    findings = [
        auth_finding("auth0", 3, 0.95),
        security_posture(),
        Finding(
            kind="captcha",
            name="turnstile_managed",
            confidence=0.94,
            extra={"visible": True, "score_based": False},
        ),
        Finding(
            kind="waf",
            name="cloudflare",
            provider="cloudflare",
            confidence=0.9,
            matched_signals=[MatchedSignal(signal_type="cookie", value="__cf_bm")],
        ),
    ]
    artifact = make_artifact(blocked=False)
    report, _ = aggregate(scan_id, "https://roundtrip.test/login", artifact, findings, STRAT)

    # upload evidence and attach refs
    refs = upload_evidence(
        scan_id,
        har_json='{"log": {}}',
        screenshot_png=b"\x89PNG\r\n\x1a\nfake",
        dom_html="<html><body>hi</body></html>",
    )
    report.artifacts = type(report.artifacts)(**refs)

    async with infra["factory"]() as session, session.begin():
        await persist_report(session, report)

    # read back everything through the DB
    async with infra["factory"]() as session:
        scan = (
            await session.execute(sa.select(Scan).where(Scan.id == uuid.UUID(scan_id)))
        ).scalar_one()
        assert scan.status == "completed"
        expected_difficulty = report.antibot.difficulty_score
        assert scan.difficulty_score == expected_difficulty
        assert scan.security_score == report.security.risk_score

        af = (
            await session.execute(
                sa.select(AuthFinding).where(AuthFinding.scan_id == uuid.UUID(scan_id))
            )
        ).scalar_one()
        assert af.provider == "auth0"
        assert "password" in af.flow
        assert af.confidence > 0.9

        sf = (
            await session.execute(
                sa.select(SecurityFinding).where(SecurityFinding.scan_id == uuid.UUID(scan_id))
            )
        ).scalar_one()
        assert sf.has_hsts is True and sf.has_csp is False
        assert sf.raw_headers.get("server") == "nginx"

        ab = (
            await session.execute(
                sa.select(AntibotFinding).where(AntibotFinding.scan_id == uuid.UUID(scan_id))
            )
        ).scalar_one()
        assert ab.captcha_type == "turnstile_managed"
        assert ab.waf_providers == ["cloudflare"]
        assert ab.cookies_detected == ["__cf_bm"]
        assert ab.difficulty_reasoning == report.antibot.difficulty_reasoning

        art = (
            await session.execute(
                sa.select(Artifacts).where(Artifacts.scan_id == uuid.UUID(scan_id))
            )
        ).scalar_one()

    # evidence objects retrievable and content intact
    client = make_client()
    assert json.loads(download(client, art.har_url))["log"] == {}
    assert download(client, art.screenshot_url) == b"\x89PNG\r\n\x1a\nfake"
    assert b"<html>" in download(client, art.dom_snapshot_url)

    # idempotent re-persist replaces rows without duplicates
    async with infra["factory"]() as session:
        async with session.begin():
            await persist_report(session, report)
        count = (
            await session.execute(
                sa.select(sa.func.count())
                .select_from(AuthFinding)
                .where(AuthFinding.scan_id == uuid.UUID(scan_id))
            )
        ).scalar_one()
        assert count == 1

    # cleanup evidence + rows
    from pipeline.evidence import parse_s3_uri

    for uri in (art.har_url, art.screenshot_url, art.dom_snapshot_url):
        if uri:
            bucket, key = parse_s3_uri(uri)
            client.delete_object(Bucket=bucket, Key=key)
    async with infra["factory"]() as session, session.begin():
        for table in (AuthFinding, SecurityFinding, AntibotFinding, Artifacts):
            await session.execute(sa.delete(table).where(table.scan_id == uuid.UUID(scan_id)))
        scan_row = await session.get(Scan, uuid.UUID(scan_id))
        if scan_row is not None:
            user_id = scan_row.user_id
            await session.execute(sa.delete(Scan).where(Scan.id == uuid.UUID(scan_id)))
            if user_id:
                await session.execute(sa.delete(ApiKey).where(ApiKey.user_id == user_id))
                await session.execute(sa.delete(User).where(User.id == user_id))
