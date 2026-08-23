"""Scan endpoints: create (single + bulk), retrieve, list/search."""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from api.deps import AuthContext, get_settings_from_request, require_api_key
from api.schemas import (
    BulkScanAccepted,
    BulkScanResult,
    ScanAccepted,
    ScanCreateRequest,
    ScanListResponse,
    ScanOptions,
    ScanSummary,
)
from api.urls import UrlRejectedError, safe_target_url
from db.models import AntibotFinding, Artifacts, AuthFinding, Scan, SecurityFinding
from pipeline.diff import compute_diff

router = APIRouter(prefix="/v1/scans", tags=["scans"])

MAX_BULK_URLS = 1000


@router.post("", status_code=202, response_model=ScanAccepted)
async def create_scan(
    body: ScanCreateRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> ScanAccepted:
    settings = get_settings_from_request(request)
    try:
        normalized = safe_target_url(body.url, settings.security.disable_ssrf_guard)
    except UrlRejectedError as exc:
        raise HTTPException(
            status_code=400, detail={"code": "url_rejected", "message": str(exc)}
        ) from exc

    session_factory = request.app.state.session_factory

    # Result cache: fresh completed result for this URL unless force=true.
    if not body.options.force:
        from workers.tasks import lookup_cached_scan

        cached_id = await lookup_cached_scan(session_factory, settings, normalized)
        if cached_id:
            scan = await _get_scan_for_user(session_factory, cached_id, auth.user_id)
            if scan is not None and scan.status == "completed":
                return ScanAccepted(scan_id=str(scan.id), status=scan.status, cached=True)

    scan_id = str(uuid.uuid4())
    async with session_factory() as session, session.begin():
        session.add(
            Scan(
                id=uuid.UUID(scan_id),
                user_id=uuid.UUID(auth.user_id),
                url=body.url,
                normalized_url=normalized,
                status="queued",
                options=body.options.model_dump(exclude={"force"}),
            )
        )

    from workers.tasks import run_scan

    run_scan.delay(scan_id)
    return ScanAccepted(scan_id=scan_id, status="queued")


@router.post("/bulk", status_code=202, response_model=BulkScanAccepted)
async def create_bulk_scan(
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> BulkScanAccepted:
    """CSV body with a ``url`` column header, up to 1000 rows."""
    settings = get_settings_from_request(request)
    raw = (await request.body()).decode("utf-8", errors="replace")
    urls = _parse_csv_urls(raw)
    if not urls:
        raise HTTPException(status_code=400, detail={
            "code": "empty_bulk", "message": "no URLs found in CSV body"})
    if len(urls) > MAX_BULK_URLS:
        raise HTTPException(status_code=400, detail={
            "code": "too_many_urls",
            "message": f"bulk scans are limited to {MAX_BULK_URLS} URLs per batch"})

    session_factory = request.app.state.session_factory
    from workers.tasks import run_scan

    batch_id = str(uuid.uuid4())
    results: list[BulkScanResult] = []
    skipped = 0

    for url in urls:
        try:
            normalized = safe_target_url(url, settings.security.disable_ssrf_guard)
        except UrlRejectedError as exc:
            skipped += 1
            results.append(BulkScanResult(url=url, error=f"url_rejected: {exc}"))
            continue
        sid = str(uuid.uuid4())
        async with session_factory() as session, session.begin():
            session.add(
                Scan(
                    id=uuid.UUID(sid),
                    user_id=uuid.UUID(auth.user_id),
                    url=url,
                    normalized_url=normalized,
                    status="queued",
                    options={"batch_id": batch_id},
                )
            )
        run_scan.delay(sid)
        results.append(BulkScanResult(url=url, scan_id=sid))

    return BulkScanAccepted(
        batch_id=batch_id, accepted=len(results) - skipped,
        skipped=skipped, results=results,
    )


def _parse_csv_urls(raw: str) -> list[str]:
    import csv
    import io

    reader = csv.DictReader(io.StringIO(raw))
    urls: list[str] = []
    for row in reader:
        value = (row.get("url") or "").strip()
        if value:
            urls.append(value)
    # also accept a bare list of URLs without header
    if not urls:
        for line in raw.splitlines():
            line = line.strip()
            if line and "://" in line:
                urls.append(line)
    return urls


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
):
    session_factory = request.app.state.session_factory
    try:
        uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={
            "code": "not_found", "message": "scan not found"}) from exc
    scan = await _get_scan_for_user(session_factory, scan_id, auth.user_id)
    if scan is None:
        raise HTTPException(status_code=404, detail={
            "code": "not_found", "message": "scan not found"})

    if scan.status not in ("completed", "waf_blocked"):
        return ScanAccepted(scan_id=str(scan.id), status=scan.status)

    settings = get_settings_from_request(request)
    report = await build_report_response(session_factory, scan, settings)
    return JSONResponse(content=report)


async def build_report_response(session_factory, scan: Scan, settings) -> dict:
    """Reconstruct the canonical report shape from DB rows."""
    from pipeline.evidence import presign_url

    async with session_factory() as session:
        af = (
            await session.execute(sa.select(AuthFinding).where(AuthFinding.scan_id == scan.id))
        ).scalar_one_or_none()
        sf = (
            await session.execute(
                sa.select(SecurityFinding).where(SecurityFinding.scan_id == scan.id)
            )
        ).scalar_one_or_none()
        ab = (
            await session.execute(
                sa.select(AntibotFinding).where(AntibotFinding.scan_id == scan.id)
            )
        ).scalar_one_or_none()
        art = (
            await session.execute(sa.select(Artifacts).where(Artifacts.scan_id == scan.id))
        ).scalar_one_or_none()

    def presign(uri: str | None) -> str | None:
        return presign_url(uri) if uri else None

    from pipeline.aggregator import DETECTION_ONLY_DISCLAIMER

    report = {
        "scan_id": str(scan.id),
        "url": scan.url,
        "status": scan.status,
        "disclaimer": DETECTION_ONLY_DISCLAIMER,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "auth": {
            "provider": af.provider if af else None,
            "confidence": af.confidence if af else None,
            "flows": af.flow if af else [],
            "evidence": (af.evidence or {}).get("matched_signals", []) if af else [],
            "other_providers": (af.evidence or {}).get("other_providers", []) if af else [],
        },
        "security": {
            "risk_score": scan.security_score,
            "has_csrf": sf.has_csrf if sf else False,
            "has_hsts": sf.has_hsts if sf else False,
            "has_csp": sf.has_csp if sf else False,
            "cookie_flags": sf.cookie_flags if sf else {},
            "mfa_detected": sf.mfa_detected if sf else False,
            "raw_headers": sf.raw_headers if sf else {},
        },
        "antibot": {
            "difficulty_score": scan.difficulty_score,
            "difficulty_reasoning": ab.difficulty_reasoning if ab else None,
            "captcha": {
                "type": ab.captcha_type if ab else None,
                "visible": ab.captcha_visible if ab else None,
            },
            "waf_providers": ab.waf_providers if ab else [],
            "fingerprinting_signals": ab.fingerprinting_signals if ab else [],
            "cookies_detected": ab.cookies_detected if ab else [],
            "evidence": (ab.evidence or {}).get("waf_evidence", []) if ab else [],
        },
        "artifacts": {
            "har_url": presign(art.har_url) if art else None,
            "screenshot_url": presign(art.screenshot_url) if art else None,
            "dom_snapshot_url": presign(art.dom_snapshot_url) if art else None,
            "trace_url": presign(art.trace_url) if art and art.trace_url else None,
        },
    }
    return report


@router.get("/{scan_id}/diff")
async def get_scan_diff(
    scan_id: str,
    request: Request,
    days: int = 30,
    auth: AuthContext = Depends(require_api_key),
):
    """What changed vs the most recent prior scan of the same URL within `days`."""
    session_factory = request.app.state.session_factory
    try:
        sid = uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={
            "code": "not_found", "message": "scan not found"}) from exc

    async with session_factory() as session:
        scan = (
            await session.execute(
                sa.select(Scan).where(Scan.id == sid,
                                      Scan.user_id == uuid.UUID(auth.user_id))
            )
        ).scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=404, detail={
                "code": "not_found", "message": "scan not found"})

        prev = await _previous_snapshot(session, scan, days)
        if prev is None:
            return {"scan_id": scan_id, "days": days, "changes": [],
                    "note": "no prior scan in window"}
        prev_snapshot = prev

    current = await build_snapshot(session_factory, scan)
    changes = compute_diff(current, prev_snapshot)
    out = changes.as_dict()
    out["days"] = days
    return JSONResponse(content=out)


async def _previous_snapshot(session, scan: Scan, days: int):
    """Most recent comparable scan of the same normalized URL inside the window."""
    import datetime as dt

    from pipeline.diff import Snapshot

    cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(days=days)
    row = (
        await session.execute(
            sa.select(Scan, AuthFinding, SecurityFinding, AntibotFinding)
            .outerjoin(AuthFinding, AuthFinding.scan_id == Scan.id)
            .outerjoin(SecurityFinding, SecurityFinding.scan_id == Scan.id)
            .outerjoin(AntibotFinding, AntibotFinding.scan_id == Scan.id)
            .where(
                Scan.normalized_url == scan.normalized_url,
                Scan.user_id == scan.user_id,
                Scan.status.in_(("completed", "waf_blocked")),
                Scan.created_at < scan.created_at,
                Scan.created_at >= cutoff,
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
    ).first()
    if row is None:
        return None
    s, af, sf, ab = row
    return Snapshot(
        scan_id=str(s.id),
        created_at=s.created_at.isoformat() if s.created_at else "",
        provider=af.provider if af else None,
        flows=list(af.flow or []) if af else [],
        captcha_type=ab.captcha_type if ab else None,
        captcha_visible=ab.captcha_visible if ab else None,
        waf_providers=list(ab.waf_providers or []) if ab else [],
        fingerprinting=list(ab.fingerprinting_signals or []) if ab else [],
        has_hsts=bool(sf.has_hsts) if sf else False,
        has_csp=bool(sf.has_csp) if sf else False,
        has_csrf=bool(sf.has_csrf) if sf else False,
        mfa_detected=bool(sf.mfa_detected) if sf else False,
        difficulty_score=s.difficulty_score,
        security_score=s.security_score,
    )


async def build_snapshot(session_factory, scan: Scan):
    """Snapshot for the given scan row (fresh session lookups)."""

    from pipeline.diff import Snapshot

    async with session_factory() as session:
        row = (
            await session.execute(
                sa.select(AuthFinding, SecurityFinding, AntibotFinding)
                .outerjoin(SecurityFinding, SecurityFinding.scan_id == AuthFinding.scan_id)
                .outerjoin(AntibotFinding, AntibotFinding.scan_id == AuthFinding.scan_id)
                .where(AuthFinding.scan_id == scan.id)
            )
        ).first()
        if row is not None:
            af, sf, ab = row
        else:
            af = None
            sf = (
                await session.execute(
                    sa.select(SecurityFinding).where(SecurityFinding.scan_id == scan.id)
                )
            ).scalar_one_or_none()
            ab = (
                await session.execute(
                    sa.select(AntibotFinding).where(AntibotFinding.scan_id == scan.id)
                )
            ).scalar_one_or_none()

    return Snapshot(
        scan_id=str(scan.id),
        created_at=scan.created_at.isoformat() if scan.created_at else "",
        provider=af.provider if af else None,
        flows=list(af.flow or []) if af else [],
        captcha_type=ab.captcha_type if ab else None,
        captcha_visible=ab.captcha_visible if ab else None,
        waf_providers=list(ab.waf_providers or []) if ab else [],
        fingerprinting=list(ab.fingerprinting_signals or []) if ab else [],
        has_hsts=bool(sf.has_hsts) if sf else False,
        has_csp=bool(sf.has_csp) if sf else False,
        has_csrf=bool(sf.has_csrf) if sf else False,
        mfa_detected=bool(sf.mfa_detected) if sf else False,
        difficulty_score=scan.difficulty_score,
        security_score=scan.security_score,
    )


async def _get_scan_for_user(session_factory, scan_id: str, user_id: str) -> Scan | None:
    async with session_factory() as session:
        try:
            sid = uuid.UUID(str(scan_id))
        except ValueError:
            return None
        scan = (
            await session.execute(
                sa.select(Scan).where(Scan.id == sid, Scan.user_id == uuid.UUID(user_id))
            )
        ).scalar_one_or_none()
        return scan


@router.get("")
async def list_scans(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    provider: str | None = None,
    captcha_type: str | None = None,
    waf_provider: str | None = None,
    min_difficulty: int | None = None,
    max_difficulty: int | None = None,
    status: str | None = None,
    auth: AuthContext = Depends(require_api_key),
) -> ScanListResponse:
    session_factory = request.app.state.session_factory
    query = sa.select(Scan).where(Scan.user_id == uuid.UUID(auth.user_id))

    if provider or captcha_type or waf_provider:
        query = query.outerjoin(AuthFinding, AuthFinding.scan_id == Scan.id).outerjoin(
            AntibotFinding, AntibotFinding.scan_id == Scan.id
        )
    if provider:
        query = query.where(AuthFinding.provider == provider)
    if captcha_type:
        query = query.where(AntibotFinding.captcha_type == captcha_type)
    if waf_provider:
        from sqlalchemy.dialects.postgresql import ARRAY

        query = query.where(
            sa.type_coerce(AntibotFinding.waf_providers, ARRAY(sa.Text)).contains(
                [waf_provider]
            )
        )
    if min_difficulty is not None:
        query = query.where(Scan.difficulty_score >= min_difficulty)
    if max_difficulty is not None:
        query = query.where(Scan.difficulty_score <= max_difficulty)
    if status:
        query = query.where(Scan.status == status)

    async with session_factory() as session:
        total = (
            await session.execute(sa.select(sa.func.count()).select_from(query.subquery()))
        ).scalar_one()
        rows = (
            await session.execute(
                query.order_by(Scan.created_at.desc()).limit(min(limit, 200)).offset(offset)
            )
        ).scalars().all()

    items = [
        ScanSummary(
            scan_id=str(s.id), url=s.url, normalized_url=s.normalized_url,
            status=s.status, difficulty_score=s.difficulty_score,
            security_score=s.security_score,
            created_at=s.created_at.isoformat() if s.created_at else None,
            completed_at=s.completed_at.isoformat() if s.completed_at else None,
        )
        for s in rows
    ]
    return ScanListResponse(total=total, items=items)


def get_options_model(options: dict | None) -> ScanOptions:
    return ScanOptions(**(options or {}))
