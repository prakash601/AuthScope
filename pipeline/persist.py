"""Persist a ScanReport into PostgreSQL (findings tables + artifacts + scan row)."""

from __future__ import annotations

import uuid

from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AntibotFinding, Artifacts, AuthFinding, Scan, SecurityFinding
from pipeline.aggregator import ScanReport


async def persist_report(session: AsyncSession, report: ScanReport) -> None:
    """Idempotently write the report; replaces any prior findings for the scan."""
    scan_id = uuid.UUID(report.scan_id)

    await session.execute(
        update(Scan)
        .where(Scan.id == scan_id)
        .values(
            status=report.status,
            difficulty_score=report.antibot.difficulty_score,
            security_score=report.security.risk_score,
            completed_at=report.completed_at,
        )
    )
    for table in (AuthFinding, SecurityFinding, AntibotFinding, Artifacts):
        await session.execute(delete(table).where(table.scan_id == scan_id))

    if report.auth.provider is not None:
        session.add(
            AuthFinding(
                scan_id=scan_id,
                provider=report.auth.provider[:50],
                flow=report.auth.flows,
                confidence=report.auth.confidence,
                evidence={
                    "matched_signals": report.auth.evidence,
                    "other_providers": report.auth.other_providers,
                },
            )
        )

    session.add(
        SecurityFinding(
            scan_id=scan_id,
            has_csrf=report.security.has_csrf,
            has_hsts=report.security.has_hsts,
            has_csp=report.security.has_csp,
            cookie_flags=report.security.cookie_flags,
            mfa_detected=report.security.mfa_detected,
            raw_headers=report.security.raw_headers,
        )
    )

    session.add(
        AntibotFinding(
            scan_id=scan_id,
            captcha_type=(report.antibot.captcha.type or "")[:50] or None,
            captcha_visible=report.antibot.captcha.visible,
            waf_providers=report.antibot.waf_providers,
            fingerprinting_signals=report.antibot.fingerprinting_signals,
            cookies_detected=report.antibot.cookies_detected,
            difficulty_reasoning=report.antibot.difficulty_reasoning,
            evidence={
                "captcha": report.antibot.captcha.model_dump(),
                "blocked_scan": report.antibot.blocked_scan,
                "waf_evidence": report.antibot.evidence,
            },
        )
    )

    if any(
        getattr(report.artifacts, col) is not None
        for col in ("har_url", "screenshot_url", "dom_snapshot_url", "trace_url")
    ):
        session.add(
            Artifacts(
                scan_id=scan_id,
                har_url=report.artifacts.har_url,
                screenshot_url=report.artifacts.screenshot_url,
                dom_snapshot_url=report.artifacts.dom_snapshot_url,
                trace_url=report.artifacts.trace_url,
            )
        )
