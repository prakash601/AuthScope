"""Scan execution task: engine pipeline + retry/blocked policy + webhooks + cache."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import UTC, datetime

import sqlalchemy as sa

from telemetry import (
    DETECTOR_DURATION,
    SCAN_DURATION,
    SCANS_TOTAL,
)
from workers.celery_app import celery_app
from workers.proxy import ProxyManager, load_proxy_manager

logger = logging.getLogger("authscope.tasks")

RESULT_CACHE_PREFIX = "resultcache:url:"


def result_cache_key(normalized_url: str) -> str:
    import hashlib

    digest = hashlib.sha256(normalized_url.encode()).hexdigest()
    return f"{RESULT_CACHE_PREFIX}{digest}"


def should_retry_blocked(attempt: int, retry_enabled: bool) -> bool:
    """ISS-022 policy: exactly one retry for blocked first attempts."""
    return attempt == 1 and retry_enabled


@celery_app.task(name="authscope.run_scan", bind=True, max_retries=0)
def run_scan(self, scan_id: str) -> str:
    """Entry point. Runs its own event loop; also safe under eager mode
    (executing inside a live loop is offloaded to a worker thread)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return _execute(scan_id)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(_execute, scan_id).result()


def _execute(scan_id: str) -> str:
    from opentelemetry import trace

    tracer = trace.get_tracer("authscope.worker")
    started = time.monotonic()
    with tracer.start_as_current_span("worker.run_scan") as span:
        span.set_attribute("authscope.scan_id", scan_id)
        status = asyncio.run(_run_scan(scan_id))
        span.set_attribute("authscope.status", status)
    SCAN_DURATION.labels(status=status).observe(time.monotonic() - started)
    SCANS_TOTAL.labels(status=status).inc()
    return status


async def _run_scan(scan_id: str) -> str:
    from config import get_settings
    from db.models import Scan
    from db.session import make_engine, make_session_factory

    settings = get_settings()
    engine = make_engine()
    session_factory = make_session_factory(engine)
    proxy_manager: ProxyManager = load_proxy_manager()

    try:
        async with session_factory() as session:
            scan = (
                await session.execute(
                    sa.select(Scan).where(Scan.id == uuid.UUID(scan_id))
                )
            ).scalar_one_or_none()
            if scan is None:
                raise ValueError(f"scan {scan_id} not found")
            url = scan.url
            normalized = scan.normalized_url or scan.url
            opts = dict(scan.options or {})
            requested_country = opts.get("proxy_country")

        await _set_status(session_factory, scan_id, "running")

        attempt = 1
        country = requested_country
        tried_countries: set[str] = {country} if country else set()

        while True:
            proxy_url = proxy_manager.get_proxy(country)
            artifact, capture = await _scan_once(settings, proxy_url, url)
            opts = {**opts, "attempts": attempt,
                    "attempted_proxies": sorted(tried_countries)}

            if not artifact.blocked or not should_retry_blocked(
                attempt, settings.scan.retry_blocked_once
            ):
                final_status = "waf_blocked" if artifact.blocked else "completed"
                await _finalize(
                    settings, session_factory, scan_id, normalized,
                    artifact, capture, final_status, opts,
                )
                logger.info(
                    "scan %s finished status=%s attempt=%d country=%s",
                    scan_id, final_status, attempt, country,
                )
                return final_status

            # Blocked on first attempt -> one retry via a different exit country.
            new_proxy, new_country = proxy_manager.get_different_country_proxy(country)
            logger.warning(
                "scan %s blocked on attempt %d (country=%s); retrying via country=%s",
                scan_id, attempt, country, new_country,
            )
            if new_proxy is not None and new_country is not None:
                country = new_country
                tried_countries.add(new_country)
            await _update_options(session_factory, scan_id, opts)
            attempt += 1
    finally:
        await engine.dispose()


async def _set_status(session_factory, scan_id: str, status: str) -> None:
    async with session_factory() as session, session.begin():
        await session.execute(
            sa.text("UPDATE scans SET status = :s WHERE id = :i").bindparams(
                s=status, i=uuid.UUID(scan_id)
            )
        )


async def _update_options(session_factory, scan_id: str, options_patch: dict) -> None:
    async with session_factory() as session, session.begin():
        await session.execute(
            sa.text("UPDATE scans SET options = CAST(:o AS jsonb) WHERE id = :i").bindparams(
                o=__import__("json").dumps(options_patch), i=uuid.UUID(scan_id)
            )
        )


async def _scan_once(settings, proxy_url: str | None, url: str):
    """One navigation attempt in a fresh browser context."""
    from engine.browser.context_manager import BrowserContextManager
    from engine.page.controller import PageController

    mgr = BrowserContextManager(timeout_seconds=settings.scan.timeout_seconds)
    await mgr.start()
    try:
        managed = await mgr.acquire(proxy_url=proxy_url)
        controller = PageController(
            lazy_captcha_wait_seconds=settings.scan.lazy_captcha_wait_seconds
        )
        result = await controller.run(managed, url)
        await mgr.release(managed)
        return result.artifact, result
    finally:
        await mgr.stop()


async def _finalize(
    settings,
    session_factory,
    scan_id: str,
    normalized_url: str,
    artifact,
    capture,
    final_status: str,
    options_patch: dict,
) -> None:
    from db.models import Scan
    from engine.detectors.auth_provider import AuthProviderDetector
    from engine.detectors.captcha import CaptchaDetector
    from engine.detectors.fingerprinting import FingerprintDetector
    from engine.detectors.security import SecurityDetector
    from engine.detectors.waf import WAFDetector
    from pipeline.aggregator import ArtifactsSection, aggregate
    from pipeline.evidence import upload_evidence
    from pipeline.persist import persist_report
    from pipeline.runner import run_detectors
    from pipeline.scoring import HeuristicScoring
    from workers.signature_cache import all_signatures, load_fresh_cache
    from workers.webhooks import dispatch_report

    cache = await load_fresh_cache(session_factory)
    signatures = all_signatures(cache)

    detectors = [
        AuthProviderDetector(signatures),
        SecurityDetector(),
        CaptchaDetector(signatures),
        WAFDetector(signatures),
        FingerprintDetector(signatures),
    ]
    outcomes = await run_detectors(detectors, artifact)
    findings = [f for outcome in outcomes for f in outcome.findings]
    for outcome in outcomes:
        DETECTOR_DURATION.labels(detector=outcome.detector).observe(
            outcome.duration_ms / 1000
        )

    report, _scores = aggregate(
        scan_id,
        artifact.url,
        artifact,
        findings,
        strategy=HeuristicScoring(),
        completed_at=datetime.now(UTC),
        status=final_status,
    )

    refs = upload_evidence(
        scan_id,
        har_json=capture.har_json,
        screenshot_png=capture.screenshot_png,
        dom_html=artifact.dom.raw_html or None,
    )
    report.artifacts = ArtifactsSection(**refs)

    webhook_pairs: list[tuple[str, str]] = []
    user_id: str | None = None
    async with session_factory() as session:
        async with session.begin():
            await persist_report(session, report)
            await session.execute(
                sa.update(Scan)
                .where(Scan.id == uuid.UUID(scan_id))
                .values(options=options_patch)
            )
        row = (
            await session.execute(
                sa.text("SELECT user_id FROM scans WHERE id = :i").bindparams(
                    i=uuid.UUID(scan_id)
                )
            )
        ).first()
        if row and row.user_id:
            user_id = str(row.user_id)
            hooks = (
                await session.execute(
                    sa.text(
                        "SELECT url, secret FROM webhooks "
                        "WHERE user_id = :u AND active = true"
                    ).bindparams(u=uuid.UUID(user_id))
                )
            ).all()
            webhook_pairs = [(r.url, r.secret) for r in hooks]

    if webhook_pairs:
        import redis.asyncio as aioredis

        redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        try:
            await dispatch_report(
                redis, webhook_pairs, report.model_dump(mode="json"), scan_id
            )
        finally:
            await redis.aclose()

    # Result cache: only completed (not blocked/failed) scans are cacheable.
    if final_status == "completed":
        import redis.asyncio as aioredis2

        ttl_hours = getattr(settings.scan, "result_cache_ttl_hours", 6)
        r2 = aioredis2.from_url(settings.redis_url, decode_responses=True)
        try:
            await r2.set(result_cache_key(normalized_url), scan_id,
                         ex=max(60, ttl_hours * 3600))
        finally:
            await r2.aclose()


async def lookup_cached_scan(session_factory, settings, normalized_url: str) -> str | None:
    """Return cached scan id for a URL if present."""
    import redis.asyncio as aioredis

    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        return await redis.get(result_cache_key(normalized_url))
    except Exception:  # noqa: BLE001 — cache must never break creation
        return None
    finally:
        await redis.aclose()
